use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallGroup {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub group_members: Vec<String>,
    pub group_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
}

impl FirewallGroup {
    pub fn get_ip_list(&self) -> Vec<String> {
        self.group_members.clone()
    }
}
