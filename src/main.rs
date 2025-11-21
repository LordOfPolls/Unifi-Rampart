mod config;
mod iplist;
mod mongo;
mod parsers;

use anyhow::Context;
use clap::Parser;
use log::{error, info, warn};
use mongodb::Database;
use crate::config::Config;

#[derive(Parser, Debug)]
#[command(name = "unifi-rampart")]
#[command(about = "Manages firewall groups in your UniFi controller", long_about = None)]
struct Cli {
    /// Erase all firewall groups
    #[arg(long)]
    clean: bool,

    /// Run in dry-run mode, does not update the database
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cfg = config::load().context("Failed to load configuration")?;

    if cli.dry_run {
        cfg.application.dry_run = true;
    }

    let log_level = cfg.application.log_level.parse().unwrap_or_else(|_| {
        eprintln!(
            "Warning: Invalid log level '{}' in config, defaulting to 'info'",
            cfg.application.log_level
        );
        log::LevelFilter::Info
    });

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    info!("Starting Unifi-Rampart");

    let client = mongo::connect(&cfg.mongodb.connection_url)
        .await
        .context("Failed to connect to MongoDB")?;

    let db = client.database(&cfg.mongodb.database_name);

    let check = sanity_check(&cfg);
    if check.is_err() {
        error!("Aborting due to configuration errors: {}", check.unwrap_err());
        return Ok(());
    }

    if cli.clean {
        if cfg.application.dry_run {
            error!("Clean mode cannot be used in dry-run mode");
            return Ok(());
        }
        op_clean(&db).await?;
    }
    else{
        op_normal(&cfg, &db).await?;
    }

    info!("Application completed successfully");
    Ok(())
}

fn sanity_check(cfg: &Config) -> Result<(), String> {
    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        if !source.url.starts_with("https") {
            if cfg.application.allow_insecure_requests {
                warn!("IP list source {} is not using HTTPS.", source.name);
            } else {
                error!(
                    "IP list source {} is not using HTTPS. Aborting!",
                    source.name
                );
                return Err(format!("IP list source {} is not using HTTPS.", source.name));
            }
        }
    }
    Ok(())
}

fn log_delta(before: &[String], after: &[String]) {
    if before.is_empty() {
        info!("New List - Contains {} IPs", after.len());
        return;
    }

    let added = after.iter().filter(|ip| !before.contains(ip)).count();
    let removed = before.iter().filter(|ip| !after.contains(ip)).count();
    info!("+{} Added, -{} Removed (total {} -> {})", added, removed, before.len(), after.len());
}

async fn op_normal(cfg: &Config, db: &Database) -> anyhow::Result<()> {
    let firewall_groups = mongo::read_firewall_groups(db)
        .await
        .context("Failed to read firewall groups")?;

    info!("Found {} firewall groups", firewall_groups.len());
    info!("Firewall groups: {:?}", firewall_groups.iter().map(|g| g.name.clone()).collect::<Vec<_>>());

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        info!("Processing iplist: {}", source.name);

        let group = firewall_groups.iter().find(|g| g.name == source.name);
        let mut before_ips: Vec<String> = Vec::new();

        if let Some(g) = group {
            let _ips = g.get_ip_list();
            if !_ips.is_empty(){
                before_ips = _ips;
            }
        }

        let resp = iplist::download(&source.url)
            .await
            .context(format!("Failed to download iplist '{}'", source.name))?;

        let ips = iplist::parse(source, &cfg.application.excluded, resp)
            .await
            .context("Failed to parse iplist")?;

        if let Err(e) = ips {
            error!("Failed to parse iplist '{}': {}", source.name, e);
            continue;
        }

        let ips = ips?;

        log_delta(&before_ips, &ips);

        if ips.len() > cfg.application.max_items_in_list {
            if !cfg.application.split_on_max_items {
                warn!(
                "IP list '{}' exceeds max items limit of {}, skipping",
                source.name, cfg.application.max_items_in_list
            );
                continue;
            } else {
                // there are more than max items in the list, split it into multiple lists, and upsert each of them
                // todo: if a list shrinks later, we should remove it from the database
                // question would then be how to handle for any firewall groups that reference it...
                warn!("IP list '{}' exceeds max items limit of {}, splitting into multiple lists", source.name, cfg.application.max_items_in_list);
                let split_ips = ips.chunks(cfg.application.max_items_in_list - 1);

                for (i, chunk) in split_ips.enumerate() {
                    if cfg.application.dry_run {
                        info!("Dry run enabled, not updating database");
                        info!("---")
                    } else {
                        mongo::upsert_iplist(db, &format!("{}_{}", source.name, i), chunk.to_vec(), &cfg.application.site_name)
                            .await
                            .context(format!("Failed to upsert iplist '{}'", source.name))?;
                    }
                }
                continue;
            }
        }

        if !cfg.application.dry_run {
            mongo::upsert_iplist(db, &source.name, ips, &cfg.application.site_name)
                .await
                .context(format!("Failed to upsert iplist '{}'", source.name))?;
        } else {
            info!("Dry run enabled, not updating database");
            info!("---")
        }
    }
    Ok(())
}
async fn op_clean(db: &Database) -> anyhow::Result<()> {
    info!("Clean mode activated");

    println!("\n\nWARNING: This will delete ALL firewall groups from the database.\
            \nThis operation cannot be undone, and may result in broken firewall rules on your UniFi controller.");
    println!("Are you sure you want to continue? (yes/no): ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read user input")?;

    let input = input.trim().to_lowercase();

    if input == "yes" || input == "y" {
        let deleted_count = mongo::delete_all_firewall_groups(db)
            .await
            .context("Failed to delete firewall groups")?;

        info!("Successfully deleted {} firewall group(s)", deleted_count);
        Ok(())
    } else {
        info!("Clean operation cancelled by user");
        Ok(())
    }
}
