use serde_json::{Value, json};
use unifi_rampart::config::ControllerConfig;
use unifi_rampart::models::unifi::FirewallGroup;
use unifi_rampart::unifi_api::UnifiClient;
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CSRF_TOKEN: &str = "test-csrf-token-abc123";

/// Credential-mode config pointed at the mock server, UniFi-OS style.
fn cred_cfg(url: &str) -> ControllerConfig {
    ControllerConfig {
        url: url.to_string(),
        site: "default".to_string(),
        is_unifi_os: true,
        verify_tls: false,
        api_key: None,
        username: Some("admin".to_string()),
        password: Some("password".to_string()),
    }
}

/// API-key-mode config pointed at the mock server, UniFi-OS style.
fn apikey_cfg(url: &str) -> ControllerConfig {
    ControllerConfig {
        url: url.to_string(),
        site: "default".to_string(),
        is_unifi_os: true,
        verify_tls: false,
        api_key: Some("my-api-key".to_string()),
        username: None,
        password: None,
    }
}

fn ok_envelope(data: Value) -> Value {
    json!({ "meta": { "rc": "ok" }, "data": data })
}

#[tokio::test]
async fn new_rejects_ambiguous_auth() {
    let server_url = "https://example.invalid";
    let mut cfg = cred_cfg(server_url);
    cfg.api_key = Some("k".to_string()); // both api_key AND creds -> invalid
    assert!(UnifiClient::new(&cfg).is_err());

    // Neither auth mode.
    let mut cfg = cred_cfg(server_url);
    cfg.username = None;
    cfg.password = None;
    assert!(UnifiClient::new(&cfg).is_err());

    // Username without password.
    let mut cfg = cred_cfg(server_url);
    cfg.password = None;
    assert!(UnifiClient::new(&cfg).is_err());
}

#[tokio::test]
async fn credential_login_and_csrf_on_mutation() {
    let server = MockServer::start().await;

    // Login endpoint returns a CSRF token header.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .and(body_json(json!({ "username": "admin", "password": "password" })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-csrf-token", CSRF_TOKEN)
                .set_body_json(ok_envelope(json!([]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    // A create (POST) must carry the captured CSRF token.
    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .and(header("x-csrf-token", CSRF_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&cred_cfg(&server.uri())).unwrap();
    client.login().await.unwrap();
    client
        .upsert_iplist("blocklist", vec!["1.2.3.4".to_string()], None)
        .await
        .unwrap();
    // Mock expectations verified on drop.
}

#[tokio::test]
async fn api_key_mode_sends_header_and_never_logs_in() {
    let server = MockServer::start().await;

    // Any hit to a login endpoint should fail the test.
    Mock::given(path("/api/auth/login"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .and(header("X-API-KEY", "my-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    client.login().await.unwrap(); // no-op
    let groups = client.read_firewall_groups().await.unwrap();
    assert!(groups.is_empty());
}

#[tokio::test]
async fn read_firewall_groups_deserializes() {
    let server = MockServer::start().await;

    let payload = ok_envelope(json!([
        {
            "_id": "5f1a2b3c4d5e6f7a8b9c0d1e",
            "name": "blocklist",
            "group_type": "address-group",
            "group_members": ["1.1.1.1", "2.2.2.2/24"],
            "site_id": "5abc000000000000000000aa"
        }
    ]));

    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .and(header("X-API-KEY", "my-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    let groups = client.read_firewall_groups().await.unwrap();

    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.id.as_deref(), Some("5f1a2b3c4d5e6f7a8b9c0d1e"));
    assert_eq!(g.name, "blocklist");
    assert_eq!(g.group_type, "address-group");
    assert_eq!(g.get_ip_list(), vec!["1.1.1.1", "2.2.2.2/24"]);
    assert_eq!(g.site_id.as_deref(), Some("5abc000000000000000000aa"));
}

#[tokio::test]
async fn upsert_create_posts_without_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .and(header("X-API-KEY", "my-api-key"))
        .and(body_json(json!({
            "name": "blocklist",
            "group_type": "address-group",
            "group_members": ["9.9.9.9"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    client
        .upsert_iplist("blocklist", vec!["9.9.9.9".to_string()], None)
        .await
        .unwrap();
}

#[tokio::test]
async fn upsert_update_puts_full_body_to_id() {
    let server = MockServer::start().await;

    let existing = FirewallGroup {
        id: Some("aabbccddeeff001122334455".to_string()),
        group_members: vec!["1.1.1.1".to_string()],
        group_type: "address-group".to_string(),
        name: "blocklist".to_string(),
        site_id: Some("5abc000000000000000000aa".to_string()),
    };

    Mock::given(method("PUT"))
        .and(path(
            "/proxy/network/api/s/default/rest/firewallgroup/aabbccddeeff001122334455",
        ))
        .and(header("X-API-KEY", "my-api-key"))
        .and(body_json(json!({
            "_id": "aabbccddeeff001122334455",
            "name": "blocklist",
            "group_type": "address-group",
            "group_members": ["8.8.8.8", "8.8.4.4"],
            "site_id": "5abc000000000000000000aa"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    client
        .upsert_iplist(
            "blocklist",
            vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            Some(&existing),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn unauthorized_triggers_single_relogin_then_succeeds() {
    let server = MockServer::start().await;

    // Login always succeeds and hands out the CSRF token. Expect exactly two
    // logins: the explicit one and the one after the 401.
    Mock::given(method("POST"))
        .and(path("/api/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-csrf-token", CSRF_TOKEN)
                .set_body_json(ok_envelope(json!([]))),
        )
        .expect(2)
        .mount(&server)
        .await;

    // First GET returns 401; after re-login the second GET succeeds. wiremock
    // matches mocks in mount order, so the limited 401 mock is mounted first
    // and consumed once, then requests fall through to the 200 mock.
    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .respond_with(ResponseTemplate::new(401).set_body_json(
            json!({ "meta": { "rc": "error", "msg": "api.err.LoginRequired" }, "data": [] }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .mount(&server)
        .await;

    let client = UnifiClient::new(&cred_cfg(&server.uri())).unwrap();
    client.login().await.unwrap();
    let groups = client.read_firewall_groups().await.unwrap();
    assert!(groups.is_empty());
}

#[tokio::test]
async fn rc_error_envelope_on_200_is_error_with_msg() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/proxy/network/api/s/default/rest/firewallgroup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "meta": { "rc": "error", "msg": "api.err.SomethingBroke" }, "data": [] }),
        ))
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    let err = client.read_firewall_groups().await.unwrap_err();
    assert!(
        err.to_string().contains("api.err.SomethingBroke"),
        "error should surface meta.msg, got: {err}"
    );
}

#[tokio::test]
async fn delete_firewall_groups_skips_referenced_group_and_counts_the_rest() {
    let server = MockServer::start().await;

    let id_ok = "aaaaaaaaaaaaaaaaaaaaaaaa";
    let id_referred = "bbbbbbbbbbbbbbbbbbbbbbbb";

    let groups = vec![
        FirewallGroup {
            id: Some(id_ok.to_string()),
            group_members: vec![],
            group_type: "address-group".to_string(),
            name: "deletable".to_string(),
            site_id: None,
        },
        FirewallGroup {
            id: Some(id_referred.to_string()),
            group_members: vec![],
            group_type: "address-group".to_string(),
            name: "in-use".to_string(),
            site_id: None,
        },
    ];

    // One delete succeeds.
    Mock::given(method("DELETE"))
        .and(path(format!(
            "/proxy/network/api/s/default/rest/firewallgroup/{id_ok}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    // The other is still referenced -> rc:error, must be skipped not fatal.
    Mock::given(method("DELETE"))
        .and(path(format!(
            "/proxy/network/api/s/default/rest/firewallgroup/{id_referred}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "meta": { "rc": "error", "msg": "api.err.ObjectReferredBy" }, "data": [] }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&apikey_cfg(&server.uri())).unwrap();
    let deleted = client.delete_firewall_groups(&groups).await.unwrap();
    assert_eq!(deleted, 1, "only the unreferenced group should be deleted");
}

#[tokio::test]
async fn classic_controller_uses_non_proxy_prefix() {
    let server = MockServer::start().await;

    let mut cfg = apikey_cfg(&server.uri());
    cfg.is_unifi_os = false;

    Mock::given(method("GET"))
        .and(path("/api/s/default/rest/firewallgroup"))
        .and(header_exists("X-API-KEY"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_envelope(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = UnifiClient::new(&cfg).unwrap();
    let groups = client.read_firewall_groups().await.unwrap();
    assert!(groups.is_empty());
}
