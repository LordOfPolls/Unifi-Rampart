use anyhow::Context;
use clap::Parser;
use log::{error, info, warn};
use std::collections::HashSet;
use std::io::IsTerminal;
use unifi_rampart::models::unifi::FirewallGroup;
use unifi_rampart::{config, iplist, unifi_api};

#[derive(Parser, Debug)]
#[command(name = "unifi-rampart")]
#[command(about = "Manages firewall groups in your UniFi controller", long_about = None)]
struct Cli {
    /// Erase firewall groups (scoped to `group_prefix` unless --clean-all is passed)
    #[arg(long)]
    clean: bool,

    /// When used with --clean and `group_prefix` is empty, confirm deleting every
    /// firewall group on the site (including ones Rampart doesn't own)
    #[arg(long)]
    clean_all: bool,

    /// Skip the interactive confirmation prompt for --clean. Required when running
    /// non-interactively (cron/systemd), since stdin isn't a terminal there.
    #[arg(long)]
    yes: bool,

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

    sanity_check(&cfg).context("Aborting due to configuration errors")?;

    let client =
        unifi_api::UnifiClient::new(&cfg.controller).context("Failed to build UniFi API client")?;

    client.login().await.context(
        "Failed to log in to UniFi controller. Check your controller URL/credentials/API key.",
    )?;

    if cli.clean {
        if cfg.application.dry_run {
            return Err(anyhow::anyhow!("Clean mode cannot be used in dry-run mode"));
        }
        op_clean(&cfg, &client, cli.clean_all, cli.yes).await?;
    } else {
        let failures = op_normal(&cfg, &client).await?;
        if failures > 0 {
            return Err(anyhow::anyhow!(
                "{} iplist(s) failed to sync; see errors above",
                failures
            ));
        }
    }

    info!("Application completed successfully");
    Ok(())
}

fn sanity_check(cfg: &config::Config) -> anyhow::Result<()> {
    if cfg.application.max_items_in_list == 0 {
        anyhow::bail!("max_items_in_list must be greater than 0");
    }

    for excluded_entry in &cfg.application.excluded {
        if iplist::parse_ip_or_network(excluded_entry).is_none() {
            anyhow::bail!(
                "Invalid IP address or network in exclusion list: {}",
                excluded_entry
            );
        }
    }

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        if !source.url.starts_with("https") && !cfg.application.allow_insecure_requests {
            anyhow::bail!("IP list source {} is not using HTTPS.", source.name);
        }
    }
    Ok(())
}

fn check_delta(before: &[String], after: &[String]) -> bool {
    if before.is_empty() {
        info!("New List - Contains {} IPs", after.len());
        return true;
    }

    let before_set: HashSet<&str> = before.iter().map(String::as_str).collect();
    let after_set: HashSet<&str> = after.iter().map(String::as_str).collect();

    let added = after_set.difference(&before_set).count();
    let removed = before_set.difference(&after_set).count();
    info!(
        "+{} Added, -{} Removed (total {} -> {})",
        added,
        removed,
        before.len(),
        after.len()
    );

    added > 0 || removed > 0
}

async fn op_normal(cfg: &config::Config, client: &unifi_api::UnifiClient) -> anyhow::Result<usize> {
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

    let mut failures = 0usize;

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        info!("Processing iplist: {}", source.name);
        let group_name = format!("{}{}", cfg.application.group_prefix, source.name);

        let resp = match iplist::download(&source.url).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to download iplist '{}': {:#}", source.name, e);
                failures += 1;
                continue;
            }
        };

        let parsed = match iplist::parse(source, &cfg.application.excluded, resp).await {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse iplist '{}': {:#}", source.name, e);
                failures += 1;
                continue;
            }
        };

        if let Err(e) = sync_group(
            cfg,
            client,
            &firewall_groups,
            &group_name,
            "address-group",
            parsed.v4,
        )
        .await
        {
            error!("Failed to sync iplist '{}': {:#}", group_name, e);
            failures += 1;
        }

        if !parsed.v6.is_empty() {
            let v6_group_name = format!("{}_v6", group_name);
            if let Err(e) = sync_group(
                cfg,
                client,
                &firewall_groups,
                &v6_group_name,
                "ipv6-address-group",
                parsed.v6,
            )
            .await
            {
                error!("Failed to sync iplist '{}': {:#}", v6_group_name, e);
                failures += 1;
            }
        }
    }
    Ok(failures)
}

async fn sync_group(
    cfg: &config::Config,
    client: &unifi_api::UnifiClient,
    firewall_groups: &[FirewallGroup],
    group_name: &str,
    group_type: &str,
    ips: Vec<String>,
) -> anyhow::Result<()> {
    if ips.len() > cfg.application.max_items_in_list {
        if !cfg.application.split_on_max_items {
            warn!(
                "IP list '{}' exceeds max items limit of {}, skipping",
                group_name, cfg.application.max_items_in_list
            );
            return Ok(());
        }
        return sync_split(cfg, client, firewall_groups, group_name, group_type, ips).await;
    }

    let group = firewall_groups.iter().find(|g| g.name == group_name);
    let before_ips = group.map(|g| g.get_ip_list()).unwrap_or_default();

    if !check_delta(&before_ips, &ips) {
        info!("No changes detected in iplist '{}'", group_name);
        return Ok(());
    }

    if cfg.application.dry_run {
        info!("Dry run enabled, not updating database");
        info!("---");
        return Ok(());
    }

    client
        .upsert_iplist(group_name, group_type, ips, group)
        .await
        .context(format!("Failed to upsert iplist '{}'", group_name))
}

/// Upload as `{group_name}_{i}` chunks, then delete stale trailing chunks
/// left over from a previous, larger run.
async fn sync_split(
    cfg: &config::Config,
    client: &unifi_api::UnifiClient,
    firewall_groups: &[FirewallGroup],
    group_name: &str,
    group_type: &str,
    ips: Vec<String>,
) -> anyhow::Result<()> {
    warn!(
        "IP list '{}' exceeds max items limit of {}, splitting into multiple lists",
        group_name, cfg.application.max_items_in_list
    );

    let chunk_count = ips.len().div_ceil(cfg.application.max_items_in_list);

    for (i, chunk) in ips.chunks(cfg.application.max_items_in_list).enumerate() {
        let chunk_name = format!("{}_{}", group_name, i);
        let existing_chunk = firewall_groups.iter().find(|g| g.name == chunk_name);
        let before_ips = existing_chunk.map(|g| g.get_ip_list()).unwrap_or_default();

        if !check_delta(&before_ips, chunk) {
            info!("No changes detected in iplist chunk '{}'", chunk_name);
            continue;
        }

        if cfg.application.dry_run {
            info!("Dry run enabled, not updating database");
            info!("---");
            continue;
        }

        client
            .upsert_iplist(&chunk_name, group_type, chunk.to_vec(), existing_chunk)
            .await
            .context(format!("Failed to upsert iplist '{}'", chunk_name))?;
    }

    if !cfg.application.dry_run {
        // The list may have shrunk since the last run; delete any chunks
        // beyond the ones we just wrote.
        let mut i = chunk_count;
        loop {
            let stale_name = format!("{}_{}", group_name, i);
            let Some(stale) = firewall_groups.iter().find(|g| g.name == stale_name) else {
                break;
            };
            match client
                .delete_firewall_groups(std::slice::from_ref(stale))
                .await
            {
                Ok(_) => info!("Deleted stale chunk '{}'", stale_name),
                Err(e) => warn!("Failed to delete stale chunk '{}': {:#}", stale_name, e),
            }
            i += 1;
        }
    }

    Ok(())
}

async fn op_clean(
    cfg: &config::Config,
    client: &unifi_api::UnifiClient,
    clean_all: bool,
    assume_yes: bool,
) -> anyhow::Result<()> {
    info!("Clean mode activated");

    let all_groups = client
        .read_firewall_groups()
        .await
        .context("Failed to read firewall groups")?;

    let prefix = &cfg.application.group_prefix;

    if prefix.is_empty() && !clean_all {
        return Err(anyhow::anyhow!(
            "group_prefix is empty, so --clean would match every firewall group on the site, \
             including ones you created by hand. Re-run with --clean-all to confirm, or set \
             group_prefix to scope deletion to Rampart's own groups."
        ));
    }

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

    let confirmed = if assume_yes {
        info!("--yes passed, skipping confirmation prompt");
        true
    } else if !std::io::stdin().is_terminal() {
        return Err(anyhow::anyhow!(
            "stdin is not a terminal; refusing to prompt interactively under cron/non-TTY. \
             Re-run with --yes to confirm non-interactively."
        ));
    } else {
        println!("Are you sure you want to continue? (yes/no): ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("Failed to read user input")?;
        let input = input.trim().to_lowercase();
        input == "yes" || input == "y"
    };

    if confirmed {
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
