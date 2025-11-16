use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
struct AwsIpRanges {
    prefixes: Vec<AwsPrefix>,
}

#[derive(Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
}

pub fn parse(text: &str) -> Result<Vec<String>> {
    let aws_ranges: AwsIpRanges =
        serde_json::from_str(text).context("Failed to parse AWS IP ranges JSON")?;

    let ips: Vec<String> = aws_ranges
        .prefixes
        .into_iter()
        .map(|prefix| prefix.ip_prefix)
        .collect();

    Ok(ips)
}
