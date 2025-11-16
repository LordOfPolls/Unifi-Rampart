mod config;
mod iplist;
mod mongo;

use anyhow::Context;
use log::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = config::load().context("Failed to load configuration")?;

    let log_level = cfg
        .application
        .log_level
        .parse()
        .unwrap_or(log::LevelFilter::Info);

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    info!("Starting Unifi-Rampart");

    let client = mongo::connect(&cfg.mongodb.connection_url)
        .await
        .context("Failed to connect to MongoDB")?;

    let db = client.database(&cfg.mongodb.database_name);

    let firewall_groups = mongo::read_firewall_groups(&db)
        .await
        .context("Failed to read firewall groups")?;

    if firewall_groups.is_empty() {
        warn!("No firewall groups found in database. This doesn't seem right... Exiting.");
        return Ok(());
    }

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        info!("Processing iplist: {}", source.name);

        let ips = iplist::download(&source.url, &cfg.application.excluded)
            .await
            .context(format!("Failed to download iplist '{}'", source.name))?;

        if !cfg.application.dry_run {
            mongo::upsert_iplist(&db, &source.name, ips, &cfg.application.site_name)
                .await
                .context(format!("Failed to upsert iplist '{}'", source.name))?;
        }else{
            info!("Dry run enabled, not updating database");

            info!("IP list: {:?}", ips);
        }
    }

    info!("Application completed successfully");
    Ok(())
}
