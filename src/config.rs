use anyhow::{Context, Result};
use config::Config as ConfigBuilder;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub mongodb: MongoConfig,
    pub iplists: IpListsConfig,
    pub application: ApplicationConfig,
}

#[derive(Debug, Deserialize)]
pub struct MongoConfig {
    pub connection_url: String,
    pub database_name: String,
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
    pub site_name: String,
    pub excluded: Vec<String>,
    pub max_items_in_list: usize,
    pub split_on_max_items: bool,
    pub dry_run: bool,
    pub allow_insecure_requests: bool,
}

pub fn load() -> Result<Config> {
    load_from_path("config")
}

#[doc(hidden)] // Internal function for testing
pub fn load_from_path(path: &str) -> Result<Config> {
    let config = ConfigBuilder::builder()
        .add_source(config::File::with_name(path))
        .build()
        .context("Failed to load config.toml")?;

    config
        .try_deserialize()
        .context("Failed to parse configuration")
}
