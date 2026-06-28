use crate::config::ControllerConfig;
use crate::models::unifi::FirewallGroup;
use anyhow::{Context, Result, anyhow};
use itertools::Itertools;
use log::{debug, info, warn};
use reqwest::{Client, Method, StatusCode, header::HeaderMap};
use serde_json::{Value, json};
use std::sync::RwLock;
use std::time::Duration;

/// How the client authenticates against the controller.
enum AuthMode {
    /// UDM / UniFi-OS API key sent via the `X-API-KEY` header. No login/session.
    ApiKey(String),
    /// Username/password login producing a session cookie (+ CSRF token).
    Credentials { username: String, password: String },
}

/// A thin client for the UniFi controller's unofficial/classic REST API.
pub struct UnifiClient {
    http: Client,
    /// Base URL without a trailing slash, e.g. "https://192.168.1.1".
    base: String,
    site: String,
    is_unifi_os: bool,
    auth: AuthMode,
    /// CSRF token captured from responses, resent on mutating requests.
    csrf: RwLock<Option<String>>,
}

impl UnifiClient {
    /// Build a client, validating that exactly one auth mode is configured
    /// (`api_key` XOR `username` + `password`).
    pub fn new(cfg: &ControllerConfig) -> Result<Self> {
        let auth = match (&cfg.api_key, &cfg.username, &cfg.password) {
            (Some(key), None, None) => AuthMode::ApiKey(key.clone()),
            (None, Some(username), Some(password)) => AuthMode::Credentials {
                username: username.clone(),
                password: password.clone(),
            },
            _ => {
                return Err(anyhow!(
                    "Exactly one auth mode must be configured: either 'api_key' \
                     alone, or both 'username' and 'password' together"
                ));
            }
        };

        let base = cfg.url.trim_end_matches('/').to_string();

        let http = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("unifi-rampart/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            http,
            base,
            site: cfg.site.clone(),
            is_unifi_os: cfg.is_unifi_os,
            auth,
            csrf: RwLock::new(None),
        })
    }

    fn is_credential_mode(&self) -> bool {
        matches!(self.auth, AuthMode::Credentials { .. })
    }

    /// Build a site-scoped API URL for `path` (no leading slash).
    fn api_url(&self, path: &str) -> String {
        if self.is_unifi_os {
            format!("{}/proxy/network/api/s/{}/{}", self.base, self.site, path)
        } else {
            format!("{}/api/s/{}/{}", self.base, self.site, path)
        }
    }

    /// Store a fresh CSRF token if the response carried one. Newer UniFi OS
    /// versions (3.x+) rotate the token and return the new value in
    /// `X-Updated-CSRF-Token` instead of resending `x-csrf-token`.
    fn capture_csrf(&self, headers: &HeaderMap) {
        let token = headers
            .get("x-updated-csrf-token")
            .or_else(|| headers.get("x-csrf-token"))
            .and_then(|val| val.to_str().ok());

        if let Some(token) = token {
            *self.csrf.write().unwrap() = Some(token.to_string());
        }
    }

    /// Log in with username/password. No-op in API-key mode.
    pub async fn login(&self) -> Result<()> {
        let (username, password) = match &self.auth {
            AuthMode::ApiKey(_) => return Ok(()),
            AuthMode::Credentials { username, password } => (username, password),
        };

        let url = if self.is_unifi_os {
            format!("{}/api/auth/login", self.base)
        } else {
            format!("{}/api/login", self.base)
        };

        debug!("Logging in to controller at {}", url);
        let body = json!({ "username": username, "password": password });
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Login request failed")?;

        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(anyhow!("Login failed: HTTP {}", status));
        }

        // Some controllers wrap the login response in the standard envelope.
        if let Ok(env) = serde_json::from_str::<Value>(&text)
            && let Some(rc) = env
                .get("meta")
                .and_then(|m| m.get("rc"))
                .and_then(|r| r.as_str())
            && rc != "ok"
        {
            let msg = env
                .get("meta")
                .and_then(|m| m.get("msg"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(anyhow!("Login failed: {}", msg));
        }

        self.capture_csrf(&headers);
        info!("Successfully logged in to controller");
        Ok(())
    }

    /// Fire a single request, applying the appropriate auth headers/body.
    async fn send_once(
        &self,
        method: &Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response> {
        let mut req = self.http.request(method.clone(), url);

        match &self.auth {
            AuthMode::ApiKey(key) => {
                req = req.header("X-API-KEY", key);
            }
            AuthMode::Credentials { .. } => {
                let mutating = matches!(*method, Method::POST | Method::PUT | Method::DELETE);
                if mutating && let Some(token) = self.csrf.read().unwrap().clone() {
                    req = req.header("x-csrf-token", token);
                }
            }
        }

        if let Some(b) = body {
            req = req.json(b);
        }

        req.send().await.context("HTTP request failed")
    }

    /// Execute a request, handling the response envelope and a single
    /// re-login + retry on auth failure (credential mode only). Returns the
    /// `data` value on success.
    async fn execute(&self, method: Method, url: &str, body: Option<Value>) -> Result<Value> {
        let mut relogin_attempted = false;

        loop {
            let resp = self.send_once(&method, url, body.as_ref()).await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            self.capture_csrf(&headers);

            let text = resp.text().await.context("Failed to read response body")?;
            let envelope: Value = if text.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&text)
                    .with_context(|| format!("Failed to parse response from {}", url))?
            };

            let rc = envelope
                .get("meta")
                .and_then(|m| m.get("rc"))
                .and_then(|r| r.as_str());
            let msg = envelope
                .get("meta")
                .and_then(|m| m.get("msg"))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();

            if status.is_success() && rc == Some("ok") {
                return Ok(envelope.get("data").cloned().unwrap_or(Value::Null));
            }

            let is_auth_error =
                status == StatusCode::UNAUTHORIZED || (rc == Some("error") && is_auth_msg(&msg));

            if is_auth_error && !relogin_attempted && self.is_credential_mode() {
                debug!("Auth failure on {}, re-logging in and retrying once", url);
                relogin_attempted = true;
                self.login().await?;
                continue;
            }

            return Err(if !status.is_success() {
                if msg.is_empty() {
                    anyhow!("Request to {} failed: HTTP {}", url, status)
                } else {
                    anyhow!("Request to {} failed: HTTP {}: {}", url, status, msg)
                }
            } else {
                anyhow!(
                    "Controller returned error for {}: {}",
                    url,
                    if msg.is_empty() {
                        "unknown error"
                    } else {
                        &msg
                    }
                )
            });
        }
    }

    /// List all firewall groups on the configured site.
    pub async fn read_firewall_groups(&self) -> Result<Vec<FirewallGroup>> {
        debug!("Fetching firewall groups");
        let url = self.api_url("rest/firewallgroup");
        let data = self.execute(Method::GET, &url, None).await?;
        let groups: Vec<FirewallGroup> =
            serde_json::from_value(data).context("Failed to deserialize firewall groups")?;
        info!("Retrieved {} firewall group(s)", groups.len());
        Ok(groups)
    }

    /// Create or update a firewall group's IP list.
    ///
    /// `existing` is the already-fetched group (looked up by name by the
    /// caller). `Some` -> PUT update; `None` -> POST create using
    /// `group_type` (e.g. `"address-group"` or `"ipv6-address-group"`).
    /// `iplist` is expected to already be deduplicated by the caller.
    pub async fn upsert_iplist(
        &self,
        group_name: &str,
        group_type: &str,
        iplist: Vec<String>,
        existing: Option<&FirewallGroup>,
    ) -> Result<()> {
        match existing {
            Some(group) => {
                let id = group
                    .id
                    .as_ref()
                    .context("Existing firewall group has no '_id'")?;
                info!(
                    "Updating firewall group '{}' with {} IP address(es)",
                    group.name,
                    iplist.len()
                );
                let updated = FirewallGroup {
                    id: group.id.clone(),
                    group_members: iplist,
                    group_type: group.group_type.clone(),
                    name: group.name.clone(),
                    site_id: group.site_id.clone(),
                };
                let body =
                    serde_json::to_value(&updated).context("Failed to serialize firewall group")?;
                let url = self.api_url(&format!("rest/firewallgroup/{}", id));
                self.execute(Method::PUT, &url, Some(body)).await?;
                info!("Successfully updated firewall group '{}'", group.name);
            }
            None => {
                info!(
                    "Creating firewall group '{}' with {} IP address(es)",
                    group_name,
                    iplist.len()
                );
                let body = json!({
                    "name": group_name,
                    "group_type": group_type,
                    "group_members": iplist,
                });
                let url = self.api_url("rest/firewallgroup");
                self.execute(Method::POST, &url, Some(body)).await?;
                info!("Successfully created firewall group '{}'", group_name);
            }
        }
        Ok(())
    }

    /// Delete the given firewall groups. Groups still referenced by an active
    /// rule (`api.err.ObjectReferredBy`) are logged and skipped rather than
    /// aborting. Returns the number actually deleted.
    pub async fn delete_firewall_groups(&self, groups: &[FirewallGroup]) -> Result<u64> {
        info!("Deleting {} firewall group(s)", groups.len());
        let mut deleted = 0u64;

        for group in groups {
            let Some(id) = &group.id else {
                warn!("Skipping firewall group '{}' with no '_id'", group.name);
                continue;
            };
            let url = self.api_url(&format!("rest/firewallgroup/{}", id));
            match self.execute(Method::DELETE, &url, None).await {
                Ok(_) => {
                    deleted += 1;
                    debug!("Deleted firewall group '{}'", group.name);
                }
                Err(e) => {
                    warn!(
                        "Skipping deletion of firewall group '{}': {}",
                        group.name, e
                    );
                }
            }
        }

        info!("Deleted {} firewall group(s)", deleted);
        Ok(deleted)
    }
}

/// Heuristic: does an `rc:"error"` message indicate an auth/login problem?
fn is_auth_msg(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("login")
        || m.contains("unauthor")
        || m.contains("no session")
        || m.contains("session expired")
}
