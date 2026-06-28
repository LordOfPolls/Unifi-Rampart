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

// hits a live external endpoint; run with cargo test -- --ignored
#[ignore]
#[tokio::test]
async fn test_e2e_google_json() {
    use crate::config::IpListSource;
    use crate::iplist;

    let source = IpListSource {
        name: "Google_Servers".to_string(),
        url: "https://www.gstatic.com/ipranges/cloud.json".to_string(),
        enabled: true,
        handler: Some("Google".to_string()),
    };

    let resp = iplist::download(&source.url)
        .await
        .expect("Failed to download");
    let parsed = iplist::parse(&source, &[], resp)
        .await
        .expect("Failed to parse");

    assert!(!parsed.v4.is_empty());
}
