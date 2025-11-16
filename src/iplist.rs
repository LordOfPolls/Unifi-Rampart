use anyhow::{Context, Error, Result};
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use regex::Regex;
use std::net::IpAddr;
use std::time::Duration;
use once_cell::sync::Lazy;
use reqwest::Response;
use crate::config::IpListSource;

static COMMENT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*[;#].*$|\/\/.*$").unwrap());

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


pub async fn download(url: &str) -> Result<Response> {
    debug!("Downloading iplist from {}", url);

    let r_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("Failed to create reqwest client")?;

    let resp = r_client.get(url).send()
        .await
        .context("Failed to download iplist")?;

    if resp.status() != 200 {
        return Err(anyhow::anyhow!("Failed to download iplist: {}", resp.status()));
    }

    debug!("Response status: {}", resp.status());
    Ok(resp)
}

pub async fn parse(source: &IpListSource, excluded: &[String], resp: Response) -> Result<Result<Vec<String>, Error>, Error> {
    let text = resp.text().await.context("Failed to read response body")?;
    let url = source.url.clone();

    let lines: Vec<String> = match source.handler.as_deref() {
        Some("AWS") => {
            crate::parsers::aws::parse(&text)
                .context("Failed to parse AWS IP ranges")?
        },
        Some("Google") => {
            crate::parsers::google::parse(&text)
                .context("Failed to parse Google Cloud IP ranges")?
        }
        _ => {
            text
                .lines()
                .map(|line| COMMENT_REGEX.replace_all(line, "").trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
    };


    let downloaded_count = text.lines().count();

    let (filtered_lines, excluded_count) = filter_excluded(lines, excluded);

    if filtered_lines.is_empty() {
        warn!("No IP addresses found in {}. This is probably fine, but check your exclusion rules.", url);
    }

    info!(
        "Downloaded {} IP addresses from iplist, filtered {} excluded IPs, keeping {}",
        downloaded_count,
        excluded_count,
        filtered_lines.len()
    );

    Ok(Ok(filtered_lines))
}
