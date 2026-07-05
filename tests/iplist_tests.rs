use ipnetwork::IpNetwork;
use std::net::IpAddr;
use unifi_rampart::config::IpListSource;
use unifi_rampart::iplist;
use unifi_rampart::iplist::{
    COMMENT_REGEX, aggregate, filter_excluded, parse_ip_or_network, should_exclude,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn plain_source(url: String) -> IpListSource {
    IpListSource {
        name: "test_feed".to_string(),
        url,
        enabled: true,
        handler: None,
    }
}
#[test]
fn test_parse_ip_or_network_single_ipv4() {
    let result = parse_ip_or_network("192.168.1.1");
    assert!(result.is_some());
    let network = result.unwrap();
    assert_eq!(network.to_string(), "192.168.1.1/32");
}

#[test]
fn test_parse_ip_or_network_single_ipv6() {
    let result = parse_ip_or_network("::1");
    assert!(result.is_some());
    let network = result.unwrap();
    assert_eq!(network.to_string(), "::1/128");
}

#[test]
fn test_parse_ip_or_network_ipv4_cidr() {
    let result = parse_ip_or_network("10.0.0.0/8");
    assert!(result.is_some());
    let network = result.unwrap();
    assert_eq!(network.to_string(), "10.0.0.0/8");
}

#[test]
fn test_parse_ip_or_network_invalid() {
    assert!(parse_ip_or_network("not-an-ip").is_none());
    assert!(parse_ip_or_network("192.168.1.1/99").is_none());
    assert!(parse_ip_or_network("").is_none());
}

#[test]
fn test_should_exclude() {
    let exclusions = vec!["192.168.0.0/16".parse::<IpNetwork>().unwrap()];

    // IP in network should be excluded
    assert!(should_exclude("192.168.1.5", &exclusions));

    // Network contained in exclusion should be excluded
    assert!(should_exclude("192.168.1.0/24", &exclusions));

    // Network containing exclusion should be excluded
    let small_exclusion = vec!["192.168.1.0/24".parse::<IpNetwork>().unwrap()];
    assert!(should_exclude("192.168.0.0/16", &small_exclusion));

    // Different network should not be excluded
    assert!(!should_exclude("10.0.0.1", &exclusions));
}

#[test]
fn test_should_exclude_ipv6() {
    let exclusions = vec!["2001:db8::/32".parse::<IpNetwork>().unwrap()];
    assert!(should_exclude("2001:db8::1", &exclusions));
}

#[test]
fn test_should_exclude_multiple() {
    let exclusions = vec![
        "192.168.0.0/16".parse::<IpNetwork>().unwrap(),
        "10.0.0.0/8".parse::<IpNetwork>().unwrap(),
    ];
    assert!(should_exclude("192.168.1.1", &exclusions));
    assert!(should_exclude("10.5.5.5", &exclusions));
    assert!(!should_exclude("172.16.0.1", &exclusions));
}

#[test]
fn test_filter_excluded() {
    let ips = vec![
        "192.168.1.1".to_string(),
        "192.168.1.2".to_string(),
        "10.0.0.1".to_string(),
    ];
    let excluded = vec!["192.168.0.0/16".to_string()];

    let (filtered, count) = filter_excluded(ips, &excluded);

    assert_eq!(filtered.len(), 1);
    assert_eq!(count, 2);
    assert_eq!(filtered[0], "10.0.0.1");
}

#[test]
fn test_filter_excluded_multiple() {
    let ips = vec![
        "192.168.1.1".to_string(),
        "192.168.1.2".to_string(),
        "10.0.0.1".to_string(),
        "10.0.0.2".to_string(),
        "172.16.0.1".to_string(),
    ];
    let excluded = vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()];

    let (filtered, count) = filter_excluded(ips, &excluded);

    assert_eq!(filtered.len(), 1);
    assert_eq!(count, 4);
    assert_eq!(filtered[0], "172.16.0.1");
}

#[test]
fn test_comment_regex() {
    // Hash comment
    let line = "192.168.1.1 # this is a comment";
    let cleaned = COMMENT_REGEX.replace_all(line, "").trim().to_string();
    assert_eq!(cleaned, "192.168.1.1");

    // No comment
    let line = "192.168.1.1";
    let cleaned = COMMENT_REGEX.replace_all(line, "").trim().to_string();
    assert_eq!(cleaned, "192.168.1.1");

    // With whitespace
    let line = "   192.168.1.1   # comment   ";
    let cleaned = COMMENT_REGEX.replace_all(line, "").trim().to_string();
    assert_eq!(cleaned, "192.168.1.1");
}

#[tokio::test]
async fn test_e2e_plain_text() {
    use unifi_rampart::config::IpListSource;
    use unifi_rampart::iplist;

    let source = IpListSource {
        name: "Firehol_level1".to_string(),
        url:
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
                .to_string(),
        enabled: true,
        handler: None,
    };

    let resp = iplist::download(&source.url)
        .await
        .expect("Failed to download");
    let parsed = iplist::parse(&source, &[], false, resp)
        .await
        .expect("Failed to parse");

    assert!(!parsed.v4.is_empty());
}

#[tokio::test]
async fn test_e2e_with_exclusions() {
    use unifi_rampart::config::IpListSource;
    use unifi_rampart::iplist;

    let source = IpListSource {
        name: "Firehol_level1".to_string(),
        url:
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
                .to_string(),
        enabled: true,
        handler: None,
    };

    let excluded = vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
    ];

    let resp = iplist::download(&source.url)
        .await
        .expect("Failed to download");
    let parsed = iplist::parse(&source, &excluded, false, resp)
        .await
        .expect("Failed to parse");

    assert!(!parsed.v4.is_empty());

    // Verify no private IPs made it through
    for ip in &parsed.v4 {
        assert!(!ip.starts_with("10."));
        assert!(!ip.starts_with("192.168."));
        assert!(!ip.starts_with("172.16."));
    }
}

#[tokio::test]
async fn parse_drops_garbage_and_partitions_v4_v6() {
    let server = MockServer::start().await;
    let body = "192.168.1.1\nnot-an-ip\n2001:db8::1\n# comment\n10.0.0.0/8\ngarbage line\n";

    Mock::given(method("GET"))
        .and(path("/list.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let source = plain_source(format!("{}/list.txt", server.uri()));
    let resp = iplist::download(&source.url).await.expect("download");
    let parsed = iplist::parse(&source, &[], false, resp)
        .await
        .expect("valid entries should still parse despite some garbage");

    assert_eq!(parsed.v4, vec!["192.168.1.1", "10.0.0.0/8"]);
    assert_eq!(parsed.v6, vec!["2001:db8::1"]);
}

#[tokio::test]
async fn parse_rejects_feed_that_looks_broken() {
    let server = MockServer::start().await;
    // Simulates an HTML error page (e.g. a Cloudflare interstitial) served with HTTP 200.
    let body = "<html>\n<head><title>503 Service Unavailable</title></head>\n<body>Error</body>\n</html>\n192.168.1.1\n";

    Mock::given(method("GET"))
        .and(path("/broken.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let source = plain_source(format!("{}/broken.txt", server.uri()));
    let resp = iplist::download(&source.url).await.expect("download");
    let err = iplist::parse(&source, &[], false, resp)
        .await
        .expect_err("mostly-garbage feed should be rejected rather than synced");

    assert!(err.to_string().contains("looks broken"));
}

#[tokio::test]
async fn parse_rejects_body_over_size_cap() {
    let server = MockServer::start().await;
    // One byte past the 50MB cap in src/iplist.rs.
    let body = "1\n".repeat(25 * 1024 * 1024 + 1);

    Mock::given(method("GET"))
        .and(path("/huge.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let source = plain_source(format!("{}/huge.txt", server.uri()));
    let resp = iplist::download(&source.url).await.expect("download");
    let err = iplist::parse(&source, &[], false, resp)
        .await
        .expect_err("oversized feed should be rejected instead of buffered in full");

    assert!(err.to_string().contains("byte cap"));
}

#[tokio::test]
async fn parse_dedupes_entries() {
    let server = MockServer::start().await;
    let body = "1.1.1.1\n1.1.1.1\n8.8.8.8\n";

    Mock::given(method("GET"))
        .and(path("/dupes.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let source = plain_source(format!("{}/dupes.txt", server.uri()));
    let resp = iplist::download(&source.url).await.expect("download");
    let parsed = iplist::parse(&source, &[], false, resp)
        .await
        .expect("parse");

    assert_eq!(parsed.v4, vec!["1.1.1.1", "8.8.8.8"]);
}

#[tokio::test]
async fn parse_aggregates_when_enabled() {
    let server = MockServer::start().await;
    let body = "1.2.3.0/25\n1.2.3.128/25\n1.2.3.5\n9.9.9.9\n";

    Mock::given(method("GET"))
        .and(path("/agg.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let source = plain_source(format!("{}/agg.txt", server.uri()));
    let resp = iplist::download(&source.url).await.expect("download");
    let parsed = iplist::parse(&source, &[], true, resp)
        .await
        .expect("parse");

    // The two adjacent /25s merge into a /24, which also swallows the
    // redundant single IP already covered by it; the unrelated IP survives
    // as a bare address (no synthetic /32).
    assert_eq!(parsed.v4, vec!["1.2.3.0/24", "9.9.9.9"]);
}

/// Every address covered by `before` must be covered by `after`, and vice
/// versa - i.e. aggregation is a pure set-preserving transform.
///
/// Compares via merged (start, end) integer ranges rather than enumerating
/// addresses: a v6 /33 alone covers 2^95 addresses, so materializing every
/// address into a `HashSet` is not viable.
fn assert_same_address_set(before: &[String], after: &[String]) {
    fn ip_to_u128(ip: IpAddr) -> u128 {
        match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        }
    }

    fn merged_ranges(entries: &[String]) -> Vec<(u128, u128)> {
        let mut ranges: Vec<(u128, u128)> = entries
            .iter()
            .map(|e| parse_ip_or_network(e).expect("valid entry"))
            .map(|net| (ip_to_u128(net.network()), ip_to_u128(net.broadcast())))
            .collect();

        ranges.sort_unstable();

        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut() {
                let adjacent_or_overlapping =
                    start <= last.1 || (last.1 != u128::MAX && start == last.1 + 1);
                if adjacent_or_overlapping {
                    if end > last.1 {
                        last.1 = end;
                    }
                    continue;
                }
            }
            merged.push((start, end));
        }
        merged
    }

    assert_eq!(merged_ranges(before), merged_ranges(after));
}

#[test]
fn aggregate_merges_adjacent_v4_cidrs() {
    let input = vec!["1.2.3.0/25".to_string(), "1.2.3.128/25".to_string()];
    let result = aggregate(input.clone());
    assert_eq!(result, vec!["1.2.3.0/24"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_drops_entries_covered_by_broader_cidr() {
    let input = vec![
        "10.0.0.0/8".to_string(),
        "10.1.2.3".to_string(),
        "10.255.255.255".to_string(),
    ];
    let result = aggregate(input.clone());
    assert_eq!(result, vec!["10.0.0.0/8"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_merges_adjacent_single_ips_into_cidr() {
    // 2.2.2.2 and 2.2.2.3 are adjacent and share a /31-aligned boundary.
    let input = vec!["2.2.2.2".to_string(), "2.2.2.3".to_string()];
    let result = aggregate(input.clone());
    assert_eq!(result, vec!["2.2.2.2/31"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_leaves_unrelated_single_ip_as_bare_address() {
    let input = vec!["5.5.5.5".to_string()];
    let result = aggregate(input.clone());
    // No merge candidates - must not gain a synthetic /32 (UniFi rejects it).
    assert_eq!(result, vec!["5.5.5.5"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_does_not_merge_non_adjacent_ranges() {
    let input = vec!["1.2.3.0/25".to_string(), "1.2.4.0/25".to_string()];
    let result = aggregate(input.clone());
    assert_eq!(result.len(), 2);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_handles_overlapping_ranges() {
    let input = vec!["1.2.3.0/24".to_string(), "1.2.3.128/25".to_string()];
    let result = aggregate(input.clone());
    assert_eq!(result, vec!["1.2.3.0/24"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_merges_adjacent_v6_cidrs() {
    let input = vec![
        "2001:db8::/33".to_string(),
        "2001:db8:8000::/33".to_string(),
    ];
    let result = aggregate(input.clone());
    assert_eq!(result, vec!["2001:db8::/32"]);
    assert_same_address_set(&input, &result);
}

#[test]
fn aggregate_is_idempotent() {
    let input = vec![
        "1.2.3.0/25".to_string(),
        "1.2.3.128/25".to_string(),
        "9.9.9.9".to_string(),
        "8.8.8.8".to_string(),
        "8.8.8.9".to_string(),
    ];
    let once = aggregate(input.clone());
    let twice = aggregate(once.clone());
    assert_eq!(once, twice);
    assert_same_address_set(&input, &once);
}

/// Exhaustive check over every subset of a small /28 (16 addresses): for
/// every subset of that space, aggregation must reproduce exactly the same
/// address set.
///
/// Unlike `assert_same_address_set`, the oracle here enumerates addresses
/// one by one via `IpNetwork::iter` rather than sorting/merging ranges -
/// a real bug in `aggregate`'s merge logic wouldn't also be baked into the
/// oracle, since it isn't the same algorithm.
#[test]
fn aggregate_preserves_address_set_exhaustively_over_small_space() {
    fn covered_addresses(entries: &[String]) -> std::collections::HashSet<std::net::Ipv4Addr> {
        entries
            .iter()
            .flat_map(|e| match parse_ip_or_network(e).expect("valid entry") {
                IpNetwork::V4(net) => net.iter(),
                IpNetwork::V6(_) => panic!("expected v4"),
            })
            .collect()
    }

    let base: u32 = u32::from(std::net::Ipv4Addr::new(203, 0, 113, 0));
    for mask in 0u32..(1 << 16) {
        let mut entries = Vec::new();
        for i in 0..16u32 {
            if mask & (1 << i) != 0 {
                let ip = std::net::Ipv4Addr::from(base + i);
                entries.push(ip.to_string());
            }
        }
        if entries.len() < 2 {
            continue;
        }
        let result = aggregate(entries.clone());
        assert_eq!(covered_addresses(&entries), covered_addresses(&result));
    }
}
