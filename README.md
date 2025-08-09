# cs-rs-firewall-bouncer

Rust port of CrowdSec Firewall Bouncer (experimental).

⚠️ Very Important: This repository is an early experiment (“vibde coded”) and is missing many features of the official Go bouncer. Expect breaking changes, incomplete implementations, and rough edges. Do not deploy to production.

## Status

- Implemented
  - Config loading (YAML, supports top-level `api_url`, `api_key`, `update_frequency` and nested `api:`)
  - Decision streaming from CrowdSec LAPI (`/v1/decisions/stream`) with filters and backoff
  - Dry-run backend
  - iptables/ipset backend (Linux) with per-origin sets; batching via `ipset restore`
  - Prometheus metrics (basic counters), `/metrics` HTTP endpoint
- Not yet implemented / partial
  - nftables, pf backends
  - Advanced iptables features, full parity with Go
  - Packaging, service management across distros
  - Extensive tests

## Quick start (local)

Requirements: Rust stable, Linux for iptables backend.

1. Build
   ```bash
   cargo build --release --features backends-iptables
   ```
2. Create config `/etc/crowdsec/bouncers/cs-firewall-bouncer.yaml` (example in `config/cs-firewall-bouncer.yaml.example`)
3. Run
   ```bash
   sudo ./target/release/cs-firewall-bouncer -c /etc/crowdsec/bouncers/cs-firewall-bouncer.yaml -v
   ```

## Quick start (Vagrant + libvirt)

1. Install libvirt provider: `vagrant plugin install vagrant-libvirt`
2. Start the box: `vagrant up --provider=libvirt`
3. Sync files if using rsync: `vagrant rsync`
4. Connect: `vagrant ssh`
5. The provisioner installs CrowdSec, generates a bouncer key, writes config from `config/cs-firewall-bouncer.yaml.example`, builds the binary, and installs a systemd service.

Check status:
```bash
systemctl status cs-firewall-bouncer | cat
journalctl -u cs-firewall-bouncer -f
```

## Configuration

Example (placeholders replaced by provisioner):
```yaml
mode: iptables
api_url: http://127.0.0.1:8080
api_key: YOUR_KEY
update_frequency: 10s
# scopes: ["ip"]
# types: ["ban"]

# Chain injection (backwards compatible with Go bouncer)
# Only configured chains are injected. If v4/v6 are not set, they inherit from iptables_chains.
# iptables_chains: ["INPUT", "FORWARD"]
# iptables_v4_chains: ["INPUT"]
# iptables_v6_chains: ["INPUT"]
```

Notes:
- Only Linux iptables/ipset backend is functional so far.
- Root privileges are required to manipulate firewall rules.
- This is experimental software; use with caution.

