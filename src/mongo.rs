use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use log::{debug, error, info};
use mongodb::bson::oid::ObjectId;
use mongodb::bson::{Bson, Document, doc};
use mongodb::{Client, Database, bson, options::ClientOptions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallGroup {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub group_members: Vec<bson::Bson>,
    pub group_type: String,
    pub name: String,
    pub site_id: String,
}

pub async fn connect(connection_url: &str) -> Result<Client> {
    info!("Connecting to MongoDB at {}", connection_url);
    let client_options = ClientOptions::parse(connection_url)
        .await
        .context("Failed to parse MongoDB connection string")?;

    let client = Client::with_options(client_options).context("Failed to create MongoDB client")?;

    info!("Successfully connected to MongoDB");
    Ok(client)
}

pub async fn read_firewall_groups(db: &Database) -> Result<Vec<FirewallGroup>> {
    debug!("Querying firewallgroup collection");
    let col: mongodb::Collection<FirewallGroup> = db.collection::<FirewallGroup>("firewallgroup");

    let mut cursor = col
        .find(None, None)
        .await
        .context("querying firewallgroup collection")?;

    let mut groups = Vec::new();

    while let Some(doc) = cursor.try_next().await? {
        debug!(
            "Found firewall group: {} (type: {})",
            doc.name, doc.group_type
        );
        groups.push(doc);
    }

    info!("Retrieved {} firewall group(s)", groups.len());
    Ok(groups)
}

pub async fn get_site_id(db: &Database, site_name: &str) -> Result<String> {
    debug!("Retrieving site ID for site: {}", site_name);
    let col: mongodb::Collection<Document> = db.collection("site");
    let filter = doc! { "attr_hidden_id": site_name };

    if let Some(doc) = col.find_one(filter, None).await? {
        if let Some(Bson::ObjectId(oid)) = doc.get("_id") {
            let site_id = oid.to_hex();
            debug!("Found site ID for '{}': {}", site_name, site_id);
            return Ok(site_id);
        }
    }

    error!("Failed to find site '{}' in database", site_name);
    Err(anyhow::anyhow!("Failed to find site '{}'", site_name))
}

pub async fn upsert_iplist(
    db: &Database,
    group_name: &str,
    iplist: Vec<String>,
    site_name: &str,
) -> Result<()> {
    debug!("Checking if firewall group '{}' exists", group_name);
    let col: mongodb::Collection<Document> = db.collection("firewallgroup");
    let filter = doc! {"name": group_name};

    if col.find_one(filter.clone(), None).await?.is_none() {
        info!(
            "Firewall group '{}' not found, creating new group",
            group_name
        );
        let site_id = get_site_id(&db, site_name).await?;

        col.insert_one(
            doc! {
                "name": group_name,
                "group_type": "address-group",
                "site_id": site_id
            },
            None,
        )
        .await
        .context("Failed to insert new firewall group")?;
        info!("Created new firewall group '{}'", group_name);
    } else {
        debug!("Firewall group '{}' already exists", group_name);
    }

    info!(
        "Updating firewall group '{}' with {} IP addresses",
        group_name,
        iplist.len()
    );
    col.update_one(filter, doc! {"$set": {"group_members": iplist}}, None)
        .await
        .context("Failed to update firewall group")?;
    info!("Successfully updated firewall group '{}'", group_name);

    Ok(())
}
