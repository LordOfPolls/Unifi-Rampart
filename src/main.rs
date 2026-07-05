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

    /// Don't delete orphaned `group_prefix`-scoped firewall groups during sync
    #[arg(long)]
    no_prune: bool,

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
        "Failed to log in to UniFi controller. Check your controller URL and credentials.",
    )?;

    if cli.clean {
        if cfg.application.dry_run {
            return Err(anyhow::anyhow!("Clean mode cannot be used in dry-run mode"));
        }
        op_clean(&cfg, &client, cli.clean_all, cli.yes).await?;
    } else {
        let failures = op_normal(&cfg, &client, !cli.no_prune).await?;
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
        if after.is_empty() {
            // Nothing existed and nothing was parsed - don't create an empty group.
            return false;
        }
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

async fn op_normal(
    cfg: &config::Config,
    client: &unifi_api::UnifiClient,
    prune: bool,
) -> anyhow::Result<usize> {
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

    // For pruning: the names this run wants to exist, and the group-name roots
    // of sources that failed (whose groups must never be pruned).
    let mut kept_names: HashSet<String> = HashSet::new();
    let mut failed_roots: Vec<String> = Vec::new();

    for source in cfg.iplists.sources.iter().filter(|s| s.enabled) {
        info!("Processing iplist: {}", source.name);
        let group_name = format!("{}{}", cfg.application.group_prefix, source.name);
        let v6_group_name = format!("{}_v6", group_name);

        let resp = match iplist::download(&source.url).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to download iplist '{}': {:#}", source.name, e);
                failures += 1;
                failed_roots.push(group_name);
                continue;
            }
        };

        let parsed = match iplist::parse(
            source,
            &cfg.application.excluded,
            cfg.application.aggregate,
            resp,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse iplist '{}': {:#}", source.name, e);
                failures += 1;
                failed_roots.push(group_name);
                continue;
            }
        };

        kept_names.extend(expected_group_names(cfg, &group_name, parsed.v4.len()));
        if !parsed.v6.is_empty() {
            kept_names.extend(expected_group_names(cfg, &v6_group_name, parsed.v6.len()));
        }

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

        if !parsed.v6.is_empty()
            && let Err(e) = sync_group(
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

    if prune
        && let Err(e) =
            prune_orphaned_groups(cfg, client, &firewall_groups, &failed_roots, &kept_names).await
    {
        error!("Failed to prune orphaned firewall groups: {:#}", e);
        failures += 1;
    }

    Ok(failures)
}

/// The exact group names `sync_group`/`sync_split` will write for `ip_count` entries.
fn expected_group_names(cfg: &config::Config, group_name: &str, ip_count: usize) -> Vec<String> {
    if ip_count > cfg.application.max_items_in_list && cfg.application.split_on_max_items {
        let chunk_count = ip_count.div_ceil(cfg.application.max_items_in_list);
        return (0..chunk_count)
            .map(|i| format!("{}_{}", group_name, i))
            .collect();
    }
    // Oversized without splitting: sync_group skips, leaving the existing group in place.
    vec![group_name.to_string()]
}

/// Whether a prefix-matched group is stale: not wanted this run, and not owned
/// by a source whose download/parse failed (we don't know its current truth).
fn is_orphaned_group(name: &str, failed_roots: &[String], kept_names: &HashSet<String>) -> bool {
    !kept_names.contains(name)
        && !failed_roots
            .iter()
            .any(|root| name == root || name.starts_with(&format!("{}_", root)))
}

/// Delete `group_prefix`-scoped groups no longer needed by any enabled source
/// (disabled/renamed sources, shrunk splits, vanished v6 entries). Groups of a
/// source that failed this run are never pruned; groups still referenced by an
/// active rule are skipped with a warning by `delete_firewall_groups`.
async fn prune_orphaned_groups(
    cfg: &config::Config,
    client: &unifi_api::UnifiClient,
    firewall_groups: &[FirewallGroup],
    failed_roots: &[String],
    kept_names: &HashSet<String>,
) -> anyhow::Result<()> {
    let prefix = &cfg.application.group_prefix;
    if prefix.is_empty() {
        // An empty prefix would match every group on the site - too broad to prune unattended.
        return Ok(());
    }

    let stale: Vec<FirewallGroup> = firewall_groups
        .iter()
        .filter(|g| g.name.starts_with(prefix.as_str()))
        .filter(|g| is_orphaned_group(&g.name, failed_roots, kept_names))
        .cloned()
        .collect();

    if stale.is_empty() {
        return Ok(());
    }

    let names = stale
        .iter()
        .map(|g| g.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    if cfg.application.dry_run {
        info!(
            "Dry run enabled, would prune {} orphaned firewall group(s): {}",
            stale.len(),
            names
        );
        return Ok(());
    }

    info!(
        "Pruning {} orphaned firewall group(s): {}",
        stale.len(),
        names
    );
    client
        .delete_firewall_groups(&stale)
        .await
        .context("Failed to prune orphaned firewall groups")?;
    Ok(())
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

/// Upload as `{group_name}_{i}` chunks. Stale trailing chunks from a previous,
/// larger run are removed by `prune_orphaned_groups`, not here.
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

#[cfg(test)]
mod prune_tests {
    use self::config::{ApplicationConfig, Config, ControllerConfig, IpListsConfig};
    use super::*;

    fn test_config(max_items_in_list: usize, split_on_max_items: bool) -> Config {
        Config {
            controller: ControllerConfig {
                url: "https://example.invalid".to_string(),
                site: "default".to_string(),
                is_unifi_os: true,
                verify_tls: false,
                username: "admin".to_string(),
                password: "password".to_string(),
            },
            iplists: IpListsConfig { sources: vec![] },
            application: ApplicationConfig {
                log_level: "info".to_string(),
                excluded: vec![],
                max_items_in_list,
                split_on_max_items,
                aggregate: false,
                dry_run: false,
                allow_insecure_requests: false,
                group_prefix: "Rampart_".to_string(),
            },
        }
    }

    #[test]
    fn expected_group_names_under_limit_is_just_the_base_name() {
        let cfg = test_config(10_000, false);
        assert_eq!(
            expected_group_names(&cfg, "Rampart_Feed", 5),
            vec!["Rampart_Feed"]
        );
    }

    #[test]
    fn expected_group_names_over_limit_without_split_keeps_base_name() {
        let cfg = test_config(10, false);
        assert_eq!(
            expected_group_names(&cfg, "Rampart_Feed", 100),
            vec!["Rampart_Feed"]
        );
    }

    #[test]
    fn expected_group_names_over_limit_with_split_lists_all_chunks() {
        let cfg = test_config(10, true);
        assert_eq!(
            expected_group_names(&cfg, "Rampart_Feed", 25),
            vec!["Rampart_Feed_0", "Rampart_Feed_1", "Rampart_Feed_2"]
        );
    }

    #[test]
    fn expected_group_names_exact_multiple_of_limit_uses_minimal_chunks() {
        let cfg = test_config(10, true);
        assert_eq!(
            expected_group_names(&cfg, "Rampart_Feed", 20),
            vec!["Rampart_Feed_0", "Rampart_Feed_1"]
        );
    }

    fn kept(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn orphaned_when_no_enabled_source_claims_the_name() {
        // Disabled/renamed source: not kept, not failed.
        assert!(is_orphaned_group("Rampart_Stale", &[], &kept(&[])));
    }

    #[test]
    fn not_orphaned_when_owning_source_failed_this_run() {
        // Download/parse failed, so we don't know its current truth - must not prune.
        let failed = vec!["Rampart_Feed".to_string()];
        assert!(!is_orphaned_group("Rampart_Feed_3", &failed, &kept(&[])));
        assert!(!is_orphaned_group("Rampart_Feed", &failed, &kept(&[])));
    }

    #[test]
    fn orphaned_stale_chunk_when_owning_source_succeeded_but_shrank() {
        // Split feed shrank from 4 chunks to 2 this run.
        let k = kept(&["Rampart_Feed_0", "Rampart_Feed_1"]);
        assert!(is_orphaned_group("Rampart_Feed_2", &[], &k));
        assert!(!is_orphaned_group("Rampart_Feed_0", &[], &k));
    }

    #[test]
    fn orphaned_when_v6_shrank_to_zero_this_run() {
        // Feed used to have v6 entries, now has none: the v6 group is stale.
        let k = kept(&["Rampart_Feed"]);
        assert!(is_orphaned_group("Rampart_Feed_v6", &[], &k));
        assert!(!is_orphaned_group("Rampart_Feed", &[], &k));
    }

    #[test]
    fn failed_root_only_protects_its_underscore_delimited_family() {
        // A failed "Rampart_Foo" must not protect "Rampart_FooBar".
        let failed = vec!["Rampart_Foo".to_string()];
        assert!(is_orphaned_group("Rampart_FooBar", &failed, &kept(&[])));
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;

    #[test]
    fn no_change_when_both_before_and_after_are_empty() {
        assert!(!check_delta(&[], &[]));
    }

    #[test]
    fn change_when_first_ever_list_is_non_empty() {
        assert!(check_delta(&[], &["1.2.3.4".to_string()]));
    }

    #[test]
    fn change_when_existing_list_shrinks_to_empty() {
        assert!(check_delta(&["1.2.3.4".to_string()], &[]));
    }

    #[test]
    fn no_change_when_lists_are_identical() {
        let list = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        assert!(!check_delta(&list, &list));
    }
}
