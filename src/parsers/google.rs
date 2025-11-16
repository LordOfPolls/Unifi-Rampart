use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
struct GoogleIpRanges {
    prefixes: Vec<GooglePrefix>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GooglePrefix {
    ipv4_prefix: Option<String>,
}

pub fn parse(text: &str) -> Result<Vec<String>> {
    let google_ranges: GoogleIpRanges =
        serde_json::from_str(text).context("Failed to parse Google Cloud IP ranges JSON")?;

    let ips: Vec<String> = google_ranges
        .prefixes
        .into_iter()
        .filter_map(|prefix| prefix.ipv4_prefix)
        .collect();

    Ok(ips)
}
