use ipnetwork::IpNetwork;
use unifi_rampart::config::IpListSource;
use unifi_rampart::iplist;
use unifi_rampart::iplist::{COMMENT_REGEX, filter_excluded, parse_ip_or_network, should_exclude};
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
    let parsed = iplist::parse(&source, &[], resp)
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
    let parsed = iplist::parse(&source, &excluded, resp)
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
    let parsed = iplist::parse(&source, &[], resp)
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
    let err = iplist::parse(&source, &[], resp)
        .await
        .expect_err("mostly-garbage feed should be rejected rather than synced");

    assert!(err.to_string().contains("looks broken"));
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
    let parsed = iplist::parse(&source, &[], resp).await.expect("parse");

    assert_eq!(parsed.v4, vec!["1.1.1.1", "8.8.8.8"]);
}
