use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use log::{debug, info};
use regex::Regex;
use std::net::IpAddr;

const STRIP_COMMENTS_REGEX: &str = r"\s*[;#].*$|\/\/.*$";

fn parse_ip_or_network(s: &str) -> Option<IpNetwork> {
    // Try parsing as a network first (with CIDR notation)
    if let Ok(network) = s.parse::<IpNetwork>() {
        return Some(network);
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        // Convert single IP to a /32 or /128 network
        return IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok();
    }

    None
}

/// Check if an IP or network should be excluded based on exclusion rules
fn should_exclude(entry: &str, exclusion_networks: &[IpNetwork]) -> bool {
    let parsed = match parse_ip_or_network(entry.trim()) {
        Some(network) => network,
        None => {
            debug!("Failed to parse IP/network: {}", entry);
            return false;
        }
    };

    // Check if this IP/network overlaps with any exclusion rule
    for excluded_net in exclusion_networks {
        // If the entry is a single IP, check if it's contained in the excluded network
        if parsed.prefix() == if parsed.is_ipv4() { 32 } else { 128 } {
            if excluded_net.contains(parsed.ip()) {
                return true;
            }
        } else {
            // If the entry is a network, check if it overlaps with the excluded network
            if excluded_net.contains(parsed.network()) || parsed.contains(excluded_net.network()) {
                return true;
            }
        }
    }

    false
}

fn filter_excluded(ips: Vec<String>, excluded: &[String]) -> (Vec<String>, usize) {
    let exclusion_networks: Vec<IpNetwork> = excluded
        .iter()
        .filter_map(|s| parse_ip_or_network(s))
        .collect();

    let mut excluded_count = 0;

    let filtered: Vec<String> = ips
        .into_iter()
        .filter(|ip| {
            if should_exclude(ip, &exclusion_networks) {
                debug!("Excluding IP/network: {}", ip);
                excluded_count += 1;
                false
            } else {
                true
            }
        })
        .collect();

    (filtered, excluded_count)
}

pub async fn download(url: &str, excluded: &[String]) -> Result<Vec<String>> {
    debug!("Downloading iplist from {}", url);

    let resp = reqwest::get(url)
        .await
        .context("Failed to download iplist")?;

    debug!("Response status: {}", resp.status());

    let text = resp.text().await.context("Failed to read response body")?;

    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();

    lines = lines
        .iter()
        .filter(|s| {
            !s.starts_with("#") && !s.starts_with("//") && !s.starts_with(";") && !s.is_empty()
        })
        .cloned()
        .collect();

    let re = Regex::new(STRIP_COMMENTS_REGEX).unwrap();
    lines = lines
        .iter()
        .map(|s| re.replace_all(s, "").to_string())
        .collect();

    let downloaded_count = lines.len();

    let (filtered_lines, excluded_count) = filter_excluded(lines, excluded);

    info!(
        "Downloaded {} IP addresses from iplist, filtered {} excluded IPs, keeping {}",
        downloaded_count,
        excluded_count,
        filtered_lines.len()
    );

    Ok(filtered_lines)
}
