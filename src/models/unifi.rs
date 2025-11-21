use anyhow::Context;
use mongodb::bson;
use mongodb::bson::oid::ObjectId;
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

impl FirewallGroup {
    pub fn get_ip_list(&self) -> Vec<String> {
        let out: Result<Vec<String>, anyhow::Error> = self.group_members.iter().map(|ip| ip.as_str().map(String::from).context("Failed to convert IP to string")).collect();

        if let Ok(out) = out {
            return out;
        }
        Vec::new()
    }
}
