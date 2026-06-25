use anyhow::Context;
use clap::Parser;
use log::{error, info, warn};
use unifi_rampart::{config, iplist, unifi_api};

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

    let client = unifi_api::UnifiClient::new(&cfg.controller)
        .context("Failed to build UniFi API client")?;

    client.login().await.context(
        "Failed to log in to UniFi controller. Check your controller URL/credentials/API key.",
    )?;

    let check = sanity_check(&cfg);
    if let Err(e) = check {
        error!(
            "Aborting due to configuration errors: {}",
            e
        );
        return Ok(());
    }

    if cli.clean {
        if cfg.application.dry_run {
            error!("Clean mode cannot be used in dry-run mode");
            return Ok(());
        }
        op_clean(&cfg, &client).await?;
    } else {
        op_normal(&cfg, &client).await?;
    }

    info!("Application completed successfully");
    Ok(())
}

fn sanity_check(cfg: &config::Config) -> Result<(), String> {
    if cfg.application.max_items_in_list == 0 {
        error!("max_items_in_list must be greater than 0");
        return Err("max_items_in_list must be greater than 0".to_string());
    }

    for excluded_entry in &cfg.application.excluded {
        if iplist::parse_ip_or_network(excluded_entry).is_none() {
            error!(
                "Invalid IP address or network in exclusion list: {}",
                excluded_entry
            );
            return Err(format!(
                "Invalid IP address or network in exclusion list: {}",
                excluded_entry
            ));
        }
    }

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        if !source.url.starts_with("https") {
            if cfg.application.allow_insecure_requests {
                warn!("IP list source {} is not using HTTPS.", source.name);
            } else {
                error!(
                    "IP list source {} is not using HTTPS. Aborting!",
                    source.name
                );
                return Err(format!(
                    "IP list source {} is not using HTTPS.",
                    source.name
                ));
            }
        }
    }
    Ok(())
}

fn check_delta(before: &[String], after: &[String]) -> bool {
    if before.is_empty() {
        info!("New List - Contains {} IPs", after.len());
        return true;
    }

    let added = after.iter().filter(|ip| !before.contains(ip)).count();
    let removed = before.iter().filter(|ip| !after.contains(ip)).count();
    info!(
        "+{} Added, -{} Removed (total {} -> {})",
        added,
        removed,
        before.len(),
        after.len()
    );

    added > 0 || removed > 0
}

async fn op_normal(cfg: &config::Config, client: &unifi_api::UnifiClient) -> anyhow::Result<()> {
    let firewall_groups = client
        .read_firewall_groups()
        .await
        .context("Failed to read firewall groups")?;

    info!("Found {} firewall groups", firewall_groups.len());
    info!(
        "Firewall groups: {:?}",
        firewall_groups
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<_>>()
    );

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        info!("Processing iplist: {}", source.name);

        let group_name = format!("{}{}", cfg.application.group_prefix, source.name);
        let group = firewall_groups.iter().find(|g| g.name == group_name);
        let mut before_ips: Vec<String> = Vec::new();

        if let Some(g) = group {
            let _ips = g.get_ip_list();
            if !_ips.is_empty() {
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

        let changed = check_delta(&before_ips, &ips);

        if !changed {
            info!("No changes detected in iplist '{}'", source.name);
            continue;
        }

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
                warn!(
                    "IP list '{}' exceeds max items limit of {}, splitting into multiple lists",
                    source.name, cfg.application.max_items_in_list
                );
                let split_ips = ips.chunks(cfg.application.max_items_in_list - 1);

                for (i, chunk) in split_ips.enumerate() {
                    if cfg.application.dry_run {
                        info!("Dry run enabled, not updating database");
                        info!("---")
                    } else {
                        let chunk_name = format!("{}_{}", group_name, i);
                        let existing_chunk =
                            firewall_groups.iter().find(|g| g.name == chunk_name);
                        client
                            .upsert_iplist(&chunk_name, chunk.to_vec(), existing_chunk)
                            .await
                            .context(format!("Failed to upsert iplist '{}'", chunk_name))?;
                    }
                }
                continue;
            }
        }

        if !cfg.application.dry_run {
            client
                .upsert_iplist(&group_name, ips, group)
                .await
                .context(format!("Failed to upsert iplist '{}'", group_name))?;
        } else {
            info!("Dry run enabled, not updating database");
            info!("---")
        }
    }
    Ok(())
}
async fn op_clean(cfg: &config::Config, client: &unifi_api::UnifiClient) -> anyhow::Result<()> {
    info!("Clean mode activated");

    let all_groups = client
        .read_firewall_groups()
        .await
        .context("Failed to read firewall groups")?;

    let prefix = &cfg.application.group_prefix;
    let targets: Vec<_> = all_groups
        .iter()
        .filter(|g| g.name.starts_with(prefix.as_str()))
        .collect();

    if targets.is_empty() {
        info!("No firewall groups match the current scope; nothing to delete");
        return Ok(());
    }

    if prefix.is_empty() {
        println!(
            "\n\nWARNING: This will delete ALL {} firewall group(s) on this site.\
                \nThis operation cannot be undone, and may result in broken firewall rules on your UniFi controller.",
            targets.len()
        );
    } else {
        println!(
            "\n\nWARNING: This will delete the {} firewall group(s) with the prefix '{}':\
                \n  {}\
                \nThis operation cannot be undone, and may result in broken firewall rules on your UniFi controller.",
            targets.len(),
            prefix,
            targets
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
    println!("Are you sure you want to continue? (yes/no): ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read user input")?;

    let input = input.trim().to_lowercase();

    if input == "yes" || input == "y" {
        let targets: Vec<_> = targets.into_iter().cloned().collect();
        let deleted_count = client
            .delete_firewall_groups(&targets)
            .await
            .context("Failed to delete firewall groups")?;

        info!("Successfully deleted {} firewall group(s)", deleted_count);
        Ok(())
    } else {
        info!("Clean operation cancelled by user");
        Ok(())
    }
}
