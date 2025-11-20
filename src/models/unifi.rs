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

