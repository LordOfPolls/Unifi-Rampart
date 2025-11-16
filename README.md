# UniFi-Rampart

Automated threat intelligence feeds for UniFi firewall groups. 
Downloads IP blocklists from Spamhaus, Firehol, abuse.ch, and other sources, then syncs them directly into your UniFi Controller's MongoDB. Run it on a schedule and stop manually updating blocklists.

This tool does **not** create firewall rules, it only creates ip groups that you can use in your own firewall rules.
This is not a substitue for proper cybersecurity, use it as an augmentation. 

## Disclaimer
> I am not responsible for any damages caused by this software. Use at your own risk.
> 
> If you bring down your entire network, that's your problem.
> 
> I have tested this extensively on my own hardware, but it's not guaranteed to work on yours. **Test it on a non-production controller first.**

## Installation

```bash
git clone https://github.com/lordofpolls/unifi-rampart.git
cd unifi-rampart
cargo build --release
```

### Building for your Unifi gateway (ARM64)

This project can be built to run directly on your controller; however, you'll probably need to cross-compile for ARM64 architecture. 
I've had success using `cross`:

```bash
# Install cross (one-time setup)
cargo install cross

cross build --release --target aarch64-unknown-linux-musl
# The binary should be at: target/aarch64-unknown-linux-musl/release/unifi-rampart
```

Deploy to your gateway:
```bash
# Copy binary and config to your gateway
scp target/aarch64-unknown-linux-musl/release/unifi-rampart root@<udm-ip>:/data/custom/unifi-rampart
scp config.toml root@<udm-ip>:/root/data/custom/unifi-rampart

# SSH in and run
ssh root@<udm-ip>
cd /root
./unifi-rampart
```

From here you can set up a cron job to fire it at regular intervals.

**Note**: When running on the UDM itself, use `mongodb://127.0.0.1:27117` in your `config.toml` since MongoDB is local.

### Running from Another Machine

You'll need access to your UniFi Controller's MongoDB instance, this means you will need to be able to SSH into the controller.

Rampart can either be run on the appliance itself, or another machine with access to the controller's MongoDB.

You can achieve the latter by using ssh tunneling:
```bash 
ssh -L 27117:127.0.0.1:27117 root@[controller-ip]
```


## Configuration

There is a config.toml file in the root directory. Edit it to match your environment.

The most important is probably `excluded` list; as this is your safety net; IPs and networks that will never be blocked even if they appear in a threat feed... 

You probably don't want to block your own private networks.

## Running It

```bash
cargo run --release
```

Each enabled source becomes a firewall group in your UniFi Controller (check **Settings → Firewall & Security → Groups**). 

The tool connects to MongoDB, downloads the ip-lists, filters out junk and excluded networks, then upserts the IP lists ~~ If a firewall group doesn't exist, it creates it. If it exists, it updates it.

For automation, use cron or systemd. Daily updates are typical, however some sources update hourly.
For home use, a daily cron job is fine:
```bash
# Cron: Daily at 2 AM
0 2 * * * cd /path/to/unifi-rampart && cargo run --release >> /var/log/unifi-rampart.log 2>&1
```

## Threat Intelligence Sources

The included config has several common feeds, but you can add any publicly accessible IP lists. Each source creates a firewall group with the specified `name`.

**Common sources:**
- **Firehol level1/2/3**: Aggregated threat feeds. Level1 is conservative (~10k IPs), level3 is aggressive (100k+ IPs). Start with level1.
- **Spamhaus DROP/EDROP**: Known spam and hijacked networks. Low false positive rate, widely trusted.
- **Emerging Threats Compromised IPs**: Active botnet nodes and compromised hosts.
- **Feodo Tracker**: Banking trojan C2 infrastructure (abuse.ch project).
- **Tor Exit Nodes**: Block Tor if your threat model requires it, but understand what you're blocking.
- **Cloudflare Servers**: Don't use these as a blocklist, instead use them as a whitelist for your webservers.

Firehol level3 and similar aggressive feeds can exceed 100,000 IPs. 
Test on non-production controllers first to avoid bringing your controller to its knees.


## Common Questions

**Will this break existing firewall rules?**

No. The tool only creates or updates firewall ip groups. Your existing rules stay untouched. The groups appear like any other address group in your controller.
You are expected to use these groups in your own firewall rules.

**What happens if a blocklist source is down?**

The tool logs the error and continues processing other sources. One failed feed won't block the entire sync.

**Can I use this with UniFi Dream Machine / Cloud Key / Cloud-hosted controllers?**

I have only tested this on UDM Pro and SE, but it should work on other UniFi devices.

**How do I actually use these firewall groups in rules?**

In your UniFi Controller: **Settings → Firewall & Security → LAN → Create Rule**. Set the source or destination to the firewall group name (e.g., `Firehol_level1`), then configure your block/reject action.

**Should I enable all the feeds?**

No. 

Start with conservative feeds (Firehol level1, Spamhaus DROP) and monitor for false positives. Adding every feed is how you accidentally block legitimate services. Tor exit nodes, for example, are only malicious if your threat model says so.

**Multiple sites?**

Change the `site_name` in config.toml to match your site (visible in the UniFi URL: `/manage/site/your_site_name`).

Note, I have not tested this with multiple sites - Here be dragons.


