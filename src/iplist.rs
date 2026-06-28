use crate::config::IpListSource;
use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{Client, Response};
use std::net::IpAddr;
use std::time::Duration;

pub static COMMENT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*[;#].*$|\/\/.*$").unwrap());

/// Shared client: one connection pool/TLS context for all feeds.
static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to build reqwest client")
});

/// The result of parsing a feed, partitioned by address family since UniFi
/// requires IPv4 and IPv6 entries to live in different group types.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedIplist {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

pub fn parse_ip_or_network(s: &str) -> Option<IpNetwork> {
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
pub fn should_exclude(entry: &str, exclusion_networks: &[IpNetwork]) -> bool {
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

pub fn filter_excluded(ips: Vec<String>, excluded: &[String]) -> (Vec<String>, usize) {
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

    let resp = HTTP_CLIENT
        .get(url)
        .send()
        .await
        .context("Failed to download iplist")?;

    if resp.status() != 200 {
        return Err(anyhow::anyhow!(
            "Failed to download iplist from {}: {}",
            url,
            resp.status()
        ));
    }

    debug!("Response status: {}", resp.status());
    Ok(resp)
}

/// Fail the whole feed when more than this fraction of lines don't parse
/// (likely an HTML error page served with HTTP 200).
const BROKEN_FEED_DROP_RATE: f64 = 0.5;

pub async fn parse(
    source: &IpListSource,
    excluded: &[String],
    resp: Response,
) -> Result<ParsedIplist> {
    let text = resp.text().await.context("Failed to read response body")?;
    let url = &source.url;

    let candidate_lines: Vec<String> = match source.handler.as_deref() {
        Some("AWS") => {
            crate::parsers::aws::parse(&text).context("Failed to parse AWS IP ranges")?
        }
        Some("Google") => crate::parsers::google::parse(&text)
            .context("Failed to parse Google Cloud IP ranges")?,
        _ => text
            .lines()
            .map(|line| COMMENT_REGEX.replace_all(line, "").trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };

    let total_candidates = candidate_lines.len();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut dropped = 0usize;

    for line in &candidate_lines {
        // Keep the original text: normalizing a bare IP to /32 or /128 gets rejected by UniFi.
        match parse_ip_or_network(line) {
            Some(net) if net.is_ipv4() => v4.push(line.clone()),
            Some(_) => v6.push(line.clone()),
            None => {
                debug!("Dropping unparseable line from '{}': {}", source.name, line);
                dropped += 1;
            }
        }
    }

    if total_candidates > 0 {
        let drop_rate = dropped as f64 / total_candidates as f64;
        if drop_rate > BROKEN_FEED_DROP_RATE {
            return Err(anyhow::anyhow!(
                "Feed '{}' looks broken: {} of {} lines ({:.0}%) failed to parse as an IP/network \
                 (an HTML error page or a changed feed format is a common cause); refusing to sync it",
                source.name,
                dropped,
                total_candidates,
                drop_rate * 100.0
            ));
        }
    }

    if dropped > 0 {
        warn!(
            "Dropped {} unparseable line(s) out of {} from feed '{}'",
            dropped, total_candidates, source.name
        );
    }

    let (v4, v4_excluded) = filter_excluded(v4, excluded);
    let (v6, v6_excluded) = filter_excluded(v6, excluded);

    let v4: Vec<String> = v4.into_iter().unique().collect();
    let v6: Vec<String> = v6.into_iter().unique().collect();

    if v4.is_empty() && v6.is_empty() {
        warn!(
            "No IP addresses found in {}. This is probably fine, but check your exclusion rules.",
            url
        );
    }

    info!(
        "Parsed '{}': {} IPv4, {} IPv6 (excluded {}, dropped {} unparseable of {} lines)",
        source.name,
        v4.len(),
        v6.len(),
        v4_excluded + v6_excluded,
        dropped,
        total_candidates
    );

    Ok(ParsedIplist { v4, v6 })
}
