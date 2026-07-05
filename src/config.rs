use anyhow::{Context, Result};
use config::Config as ConfigBuilder;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub controller: ControllerConfig,
    pub iplists: IpListsConfig,
    pub application: ApplicationConfig,
}

#[derive(Debug, Deserialize)]
pub struct ControllerConfig {
    /// Base URL of the controller, e.g. "https://192.168.1.1" (trailing slash is normalized away).
    pub url: String,
    /// Site shortname, e.g. "default".
    pub site: String,
    /// true = UniFi OS `/proxy/network` prefix, false = classic self-hosted `:8443` style.
    #[serde(default = "default_true")]
    pub is_unifi_os: bool,
    /// false = accept self-signed certs (common for local controllers).
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    pub username: String,
    pub password: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct IpListsConfig {
    pub sources: Vec<IpListSource>,
}

#[derive(Debug, Deserialize)]
pub struct IpListSource {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub handler: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApplicationConfig {
    pub log_level: String,
    pub excluded: Vec<String>,
    pub max_items_in_list: usize,
    pub split_on_max_items: bool,
    /// Merge adjacent/overlapping CIDR ranges before syncing; never changes what a list covers.
    #[serde(default)]
    pub aggregate: bool,
    pub dry_run: bool,
    pub allow_insecure_requests: bool,
    /// Prepended to every firewall group name Rampart manages. Empty by default.
    #[serde(default)]
    pub group_prefix: String,
}

pub fn load() -> Result<Config> {
    load_from_path("config")
}

#[doc(hidden)] // Internal function for testing
pub fn load_from_path(path: &str) -> Result<Config> {
    let config = ConfigBuilder::builder()
        .add_source(config::File::with_name(path))
        .add_source(config::Environment::with_prefix("RAMPART").separator("__"))
        .build()
        .context("Failed to load config.toml")?;

    config
        .try_deserialize()
        .context("Failed to parse configuration")
}
