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

#[tokio::test]
async fn test_e2e_aws_json() {
    use crate::config::IpListSource;
    use crate::iplist;

    let source = IpListSource {
        name: "AWS_Servers".to_string(),
        url: "https://ip-ranges.amazonaws.com/ip-ranges.json".to_string(),
        enabled: true,
        handler: Some("AWS".to_string()),
    };

    let resp = iplist::download(&source.url)
        .await
        .expect("Failed to download");
    let result = iplist::parse(&source, &[], resp)
        .await
        .expect("Failed to parse");
    let ips = result.expect("Parsing returned error");

    assert!(!ips.is_empty());
}
