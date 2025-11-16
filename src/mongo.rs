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
    pub site_id: ObjectId,
}

pub async fn connect(connection_url: &str) -> Result<Client> {
    info!("Connecting to MongoDB at {}", connection_url);
    let client_options = ClientOptions::parse(connection_url)
        .await
        .context("Failed to parse MongoDB connection string")?;

    let client = Client::with_options(client_options).context("Failed to create MongoDB client")?;

    let r = client.database("admin").run_command(doc! {"ping": 1}, None).await;

    if r.is_err() {
        error!("Failed to connect to MongoDB. Is your ssh tunnel running?\n{}", r.clone().unwrap_err());
        #[allow(clippy::unnecessary_unwrap)]
        return Err(r.unwrap_err().into());
    }

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

pub async fn get_site_id(db: &Database, site_name: &str) -> Result<ObjectId> {
    debug!("Retrieving site ID for site: {}", site_name);
    let col: mongodb::Collection<Document> = db.collection("site");
    let filter = doc! { "attr_hidden_id": site_name };

    if let Some(doc) = col.find_one(filter, None).await?
        && let Some(Bson::ObjectId(oid)) = doc.get("_id") {
            let site_id = oid.to_hex();
            debug!("Found site ID for '{}': {}", site_name, site_id);
            return Ok(*oid);
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
    let col: mongodb::Collection<Document> = db.collection("firewallgroup");
    let filter = doc! {"name": group_name};

    // only used for logging
    let exists = col.find_one(filter.clone(), None).await?.is_some();

    if !exists {
        info!("Firewall group '{}' not found, will create", group_name);
        let site_id = get_site_id(db, site_name).await?;

        let update = doc! {
              "$setOnInsert": {
                  "name": group_name,
                  "group_type": "address-group",
                  "site_id": site_id
              },
              "$set": {
                  "group_members": iplist
              }
          };

        let options = mongodb::options::UpdateOptions::builder()
            .upsert(true)
            .build();

        col.update_one(filter, update, options)
            .await
            .context("Failed to upsert firewall group")?;

        info!("Created and updated firewall group '{}'", group_name);
    } else {
        info!("Updating existing firewall group '{}' with {} IP addresses",
                group_name, iplist.len());

        col.update_one(
            filter,
            doc! {"$set": {"group_members": iplist}},
            None
        )
            .await
            .context("Failed to update firewall group")?;

        info!("Successfully updated firewall group '{}'", group_name);
    }

    Ok(())
}
