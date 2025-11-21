use ipnetwork::IpNetwork;
use unifi_rampart::iplist::{COMMENT_REGEX, filter_excluded, parse_ip_or_network, should_exclude};
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
    let result = iplist::parse(&source, &[], resp)
        .await
        .expect("Failed to parse");
    let ips = result.expect("Parsing returned error");

    assert!(!ips.is_empty());
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
    let result = iplist::parse(&source, &excluded, resp)
        .await
        .expect("Failed to parse");
    let ips = result.expect("Parsing returned error");

    assert!(!ips.is_empty());

    // Verify no private IPs made it through
    for ip in &ips {
        assert!(!ip.starts_with("10."));
        assert!(!ip.starts_with("192.168."));
        assert!(!ip.starts_with("172.16."));
    }
}
