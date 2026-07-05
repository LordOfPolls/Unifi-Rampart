# UniFi-Rampart

<p align="center">
  <strong>Automated threat intelligence feeds for UniFi firewalls</strong>
</p>

<p align="center">
  <img width="389" height="512" alt="UniFi-Rampart Dashboard" src="https://github.com/user-attachments/assets/60a5531b-e33c-4993-b9a0-0651e34a6203" />
</p>
<p align="center">
  <a href="https://github.com/lordofpolls/unifi-rampart/actions/workflows/rust.yml">
    <img src="https://github.com/lordofpolls/unifi-rampart/actions/workflows/rust.yml/badge.svg" alt="CI Status">
  </a>
  <a href="https://github.com/lordofpolls/unifi-rampart/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/lordofpolls/unifi-rampart" alt="License">
  </a>
</p>
Downloads and syncs curated IP blocklists from Spamhaus DROP, Firehol, Emerging Threats, Feodo Tracker, and abuse.ch directly into your UniFi Controller's firewall groups.

Written in Rust for performance and reliability.

Run it on a schedule and stop manually updating blocklists.

> [!Note]
> This tool does **not** create firewall rules, it only creates IP groups that you can use in your own firewall rules.
> This is not a substitute for proper cybersecurity - use it as an augmentation.

---


## Disclaimer

> [!CAUTION]
> I am not responsible for any damages caused by this software. Use at your own risk.
> 
> If you bring down your entire network, that's your problem.
> 
> I have tested this extensively on my own hardware, but it's not guaranteed to work on yours. **Test it on a non-production controller first.**
>
> Use common-sense, create backups, and test before applying to production! 

---

## Installation

```bash
git clone https://github.com/lordofpolls/unifi-rampart.git
cd unifi-rampart
cargo build --release
```

### Building for UniFi Gateway (ARM64)

> [!TIP]
> To run directly on your UDM/UDR, you'll need to cross-compile for ARM64 architecture.
```bash
# Install cross (one-time setup)
cargo install cross

# Build for ARM64
cross build --release --target aarch64-unknown-linux-musl
```

The binary will be at: `target/aarch64-unknown-linux-musl/release/unifi-rampart`

**Deploy to your gateway:**
```bash
# Copy binary and config to your gateway
scp target/aarch64-unknown-linux-musl/release/unifi-rampart root@<gateway-ip>:/data/custom/unifi-rampart
scp config.toml root@<gateway-ip>:/data/custom/unifi-rampart

# SSH in and run
ssh root@<gateway-ip>
cd /data/custom/unifi-rampart
./unifi-rampart
```

From here you can set up a cron job to fire it at regular intervals.

> [!NOTE]
> When running on the gateway itself, set `url = "https://127.0.0.1"` and `verify_tls = false` in your `config.toml`. No SSH tunnel is needed - this is a normal HTTPS API call, not a raw MongoDB protocol connection.

### Running from Another Machine

You can run Rampart on any machine with network access to your controller over HTTPS. Just point `url` in `config.toml` at the controller's real address (e.g. `https://192.168.1.1`), keeping `verify_tls = false` if it uses a self-signed certificate.

### Getting API Credentials

You need either an API key or a username/password pair (not both):

- **API key (recommended, UDM/UniFi OS controllers)**: Generate a local API key from the controller's UI, under Settings > Control Plane > Integrations (the exact path varies by firmware version). Set it as `api_key` in `config.toml`.
- **Username/password (classic self-hosted controllers)**: Create a local admin account and set `username`/`password` in `config.toml`. Disable 2FA on this account - this flow does not handle 2FA challenges.

## Configuration

Copy `config.example.toml` to `config.toml` and edit it to match your environment (`config.toml` is gitignored since it will contain your controller credentials).

The most important is probably `excluded` list; as this is your safety net; IPs and networks that will never be blocked even if they appear in a threat feed... 

You probably don't want to block your own private networks.

## Running It

### Basic Usage
```bash
cargo run --release
```

**What happens:**
1. Logs in to your UniFi controller's API
2. Downloads IP lists from enabled sources
3. Filters out junk and excluded networks
4. Creates/updates firewall groups in UniFi Controller

Each enabled source becomes a firewall group visible in **Settings → Policy Engine → Zones**

### Command-Line Options

**Dry Run Mode:**
```bash
cargo run --release -- --dry-run
```
Overrides your config and runs in dry-run mode.
Simulates the sync without making any database changes. Use this to preview what would be updated before applying changes to production.

**Clean Mode:**
```bash
cargo run --release -- --clean
```
Deletes firewall groups from the controller, should only be used as a last resort. If `group_prefix` is set in `config.toml`, only groups whose name starts with that prefix are deleted; if it's empty, all firewall groups on the site are deleted.

> [!CAUTION]
> This operation cannot be undone and may break existing firewall rules that reference these groups.

**Pruning (on by default):**

Every normal sync also deletes any `group_prefix`-scoped firewall group that no longer corresponds to an enabled source - for example after you disable or rename a source, or a split feed shrinks and needs fewer `_0`, `_1`, ... chunk groups. A group is only pruned once Rampart has successfully re-downloaded and re-parsed the sources it might belong to for this run, so a transient download failure never causes a group to be deleted. Groups still referenced by an active firewall rule are skipped with a warning, same as `--clean`. Requires `group_prefix` to be set.

To disable pruning and leave orphaned groups in place:
```bash
cargo run --release -- --no-prune
```

## Threat Intelligence Sources

The included config has several common feeds, but you can add any publicly accessible IP lists. Each source creates a firewall group with the specified `name`.

**Common sources:**
- **Firehol level1/2/3**: Aggregated threat feeds. Level1 is conservative, level2 and 3 are aggressive (100k+ IPs). Start with level1.
- **Spamhaus DROP/EDROP**: Known spam and hijacked networks. Low false positive rate, widely trusted.
- **Emerging Threats Compromised IPs**: Active botnet nodes and compromised hosts.
- **Feodo Tracker**: Banking trojan C2 infrastructure (abuse.ch project).
- **Tor Exit Nodes**: Block Tor if your threat model requires it, but understand what you're blocking.
- **Cloudflare Servers**: Don't use these as a blocklist, instead use them as a whitelist for your webservers.

Aggressive feeds like Firehol Level3 can exceed 100,000 IPs and may overwhelm your controller.
Test on non-production controllers first to avoid bringing your controller to its knees.

---

## FAQ

<details>
<summary><strong> My console says "Gateway Configuration Failed"</strong></summary>

Likely, one of the firewall groups you've enabled is too large for your controller.

**Solution:**
1. Reduce the number of IPs in each group, or disable the feed
2. Delete the offending groups from the controller

> [!WARNING]
> UniFi will refuse to load a config if there's a list that's too large, even if it isn't used in any rules.

Find the offending group:
```bash
sudo cat /usr/lib/unifi/logs/server.log | grep -E "ERROR|WARN" | grep -v "trafficFlow"
```

**Option 1 - Use clean mode (easiest):**
```bash
cargo run --release -- --clean
```
This will delete all firewall groups. After cleaning, disable the problematic feed in `config.toml` before syncing again.

**Option 2 - Manual deletion:**
Delete the offending firewall group(s) via the UniFi web UI (Settings → Firewall & Security → Firewall Groups, or similar depending on firmware version) using the names/IDs from the error messages. 

> [!NOTE]
> The maximum size of a firewall group appears to be around 10,000 IPs (educated guess)
> If you try and sync a list larger than this, your controller will refuse to load the config until you manually remove it. 

</details>

<details>
<summary><strong>Will this break existing firewall rules?</strong></summary>

**No.** The tool only creates or updates firewall IP groups. Your existing rules stay untouched. The groups appear like any other address group in your controller.
If you have a rule that depends on these groups, it will pick up the changes without issue.

You are expected to use these groups in your own firewall rules.

</details>

<details>
<summary><strong>What happens if a blocklist source is down?</strong></summary>

The tool logs the error and continues processing other sources. One failed feed won't block the entire sync.

</details>

<details>
<summary><strong>Can I use this with UDM/Cloud Key/Cloud-hosted controllers?</strong></summary>

I have only tested this on UDM Pro and SE, but it should work on other UniFi devices that expose the controller's REST API.

</details>

<details>
<summary><strong>How do I actually use these firewall groups in rules?</strong></summary>

1. Go to **Settings → Policy Engine → Zones**
2. Create a new rule
3. Set the mode to IP, then list (out of the list, Any, IP, MAC, Region)
4. Choose your desired group
5. Configure your block/reject action
6. Save and apply

</details>

<details>
<summary><strong>Should I enable all the feeds?</strong></summary>

**No.**

Start with conservative feeds (Firehol Level1, Spamhaus DROP) and monitor for false positives. Adding every feed is how you accidentally block legitimate services.

> [!TIP]
> Tor exit nodes, for example, are only malicious if your threat model requires blocking them.

</details>

<details>
<summary><strong>Multiple sites?</strong></summary>

Change the `site` in `config.toml` under `[controller]` to match your site (visible in the UniFi URL: `/manage/site/your_site_name`).

I have not tested this with multiple sites - Here be dragons.

</details>



