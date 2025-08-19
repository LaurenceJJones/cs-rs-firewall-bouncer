#![cfg(all(feature = "backends-iptables", target_os = "linux"))]

use crate::api::Decision;
use crate::backend::{FirewallBackend, BackendMetricsCollector};
use crate::config::{Config, DenyAction};
use crate::metrics;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone, Debug)]
pub struct IptablesMetricsConfig {
    pub chain: String,
    pub set_v4_prefix: String,
    pub set_v6_prefix: String,
    pub iptables_save_bin: String,
    pub ip6tables_save_bin: String,
    pub ipset_bin: String,
}

pub struct IptablesBackend {
    // binaries
    iptables_bin: String,
    ip6tables_bin: String,
    ipset_bin: String,

    // config
    table: String,
    chain: String,
    injection_chains_v4: Vec<String>,
    injection_chains_v6: Vec<String>,
    set_v4: String,
    set_v6: String,
    set_type: String,
    set_size: u32,
    deny_action: DenyAction,
    ipv4: bool,
    ipv6: bool,

    // pending operations for batching
    pending_add_v4: Vec<String>,
    pending_add_v6: Vec<String>,
    pending_del_v4: Vec<String>,
    pending_del_v6: Vec<String>,
}

impl IptablesBackend {
    pub fn new(cfg: &Config) -> Self {
        let ic = cfg.iptables.as_ref().expect("iptables config should be present after defaults");
        let set_type = ic.set_type.clone().unwrap_or_else(|| "nethash".to_string());
        let set_type = map_set_type_to_ipset(&set_type);
        // Determine injection chains with inheritance.
        // Prefer nested iptables.* chains if provided; otherwise fall back to top-level.
        let base_chains_nested: Vec<String> = cfg
            .iptables
            .as_ref()
            .and_then(|i| i.chains.clone())
            .unwrap_or_default();
        let v4_nested: Vec<String> = cfg.iptables.as_ref().and_then(|i| i.v4_chains.clone()).unwrap_or_default();
        let v6_nested: Vec<String> = cfg.iptables.as_ref().and_then(|i| i.v6_chains.clone()).unwrap_or_default();

        let base_chains_top: Vec<String> = cfg.iptables_chains.clone().unwrap_or_default();
        let v4_top: Option<Vec<String>> = cfg.iptables_v4_chains.clone();
        let v6_top: Option<Vec<String>> = cfg.iptables_v6_chains.clone();

        let base_chains = if !base_chains_nested.is_empty() { base_chains_nested } else { base_chains_top };
        // Determine specific chains: prefer nested if provided, else top-level, else empty
        let v4_specific = if !v4_nested.is_empty() { v4_nested } else { v4_top.unwrap_or_default() };
        let v6_specific = if !v6_nested.is_empty() { v6_nested } else { v6_top.unwrap_or_default() };

        // Final lists: chains applies to both, and v4/v6 add family-specific chains
        fn combine_chains(mut base: Vec<String>, specific: Vec<String>) -> Vec<String> {
            for ch in specific {
                if !base.contains(&ch) {
                    base.push(ch);
                }
            }
            base
        }
        let injection_chains_v4: Vec<String> = combine_chains(base_chains.clone(), v4_specific);
        let injection_chains_v6: Vec<String> = combine_chains(base_chains, v6_specific);
        // Determine ipv4/ipv6 enabled flags from global config
        let global_ipv4 = cfg.ipv4.unwrap_or(true);
        let global_ipv6 = cfg.ipv6.unwrap_or(true);

        Self {
            iptables_bin: ic.iptables_path.clone().unwrap_or_else(|| "iptables".to_string()),
            ip6tables_bin: ic.ip6tables_path.clone().unwrap_or_else(|| "ip6tables".to_string()),
            ipset_bin: ic.ipset_path.clone().unwrap_or_else(|| "ipset".to_string()),
            table: ic.table.clone().unwrap_or_else(|| "filter".to_string()),
            chain: ic.chain.clone().unwrap_or_else(|| "CROWDSEC_CHAIN".to_string()),
            injection_chains_v4,
            injection_chains_v6,
            set_v4: ic.set_name_v4.clone().unwrap_or_else(|| "crowdsec-blacklist".to_string()),
            set_v6: ic.set_name_v6.clone().unwrap_or_else(|| "crowdsec6-blacklist".to_string()),
            set_type,
            set_size: ic.set_size.unwrap_or(131072),
            deny_action: ic.deny_action.clone().unwrap_or(DenyAction::Drop),
            ipv4: global_ipv4,
            ipv6: global_ipv6,
            pending_add_v4: Vec::new(),
            pending_add_v6: Vec::new(),
            pending_del_v4: Vec::new(),
            pending_del_v6: Vec::new(),
        }
    }

    fn ensure_binaries(&self) -> Result<()> {
        which::which(&self.ipset_bin).with_context(|| format!("{} binary not found", self.ipset_bin))?;
        which::which(&self.iptables_bin).with_context(|| format!("{} binary not found", self.iptables_bin))?;
        which::which(&self.ip6tables_bin).with_context(|| format!("{} binary not found", self.ip6tables_bin))?;
        Ok(())
    }

    fn run_cmd(&self, bin: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(bin).args(args).output().with_context(|| format!("failed to run {} {:?}", bin, args))?;
        if !output.status.success() {
            return Err(anyhow!(
                "{} {:?} failed: status={} stderr={}",
                bin,
                args,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    fn run_cmd_capture_stdout(&self, bin: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(bin)
            .args(args)
            .output()
            .with_context(|| format!("failed to run {} {:?}", bin, args))?;
        if !output.status.success() {
            return Err(anyhow!(
                "{} {:?} failed: status={} stderr={}",
                bin,
                args,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn check_cmd(&self, bin: &str, args: &[&str]) -> bool {
        match Command::new(bin).args(args).output() {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    fn ensure_ipset(&self, set_name: &str, family: &str) -> Result<()> {
        // ipset create -exist <name> <type> family <inet|inet6> maxelem <size>
        self.run_cmd(
            &self.ipset_bin,
            &["create", set_name, &self.set_type, "family", family, "maxelem", &self.set_size.to_string(), "-exist"],
        )
    }

    fn ensure_chain_exists(&self, ip6: bool) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        // Check if chain exists
        if !self.check_cmd(bin, &["-t", &self.table, "-S", &self.chain]) {
            // Create chain
            self.run_cmd(bin, &["-t", &self.table, "-N", &self.chain])?;
        }
        Ok(())
    }

    fn remove_jump_from_chains(&self, ip6: bool, chains: &[String]) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        for ch in chains {
            // Remove all occurrences in case multiple were inserted
            loop {
                if self.check_cmd(bin, &["-t", &self.table, "-C", ch, "-j", &self.chain]) {
                    // Best-effort delete; if it fails, bail to avoid infinite loop
                    self.run_cmd(bin, &["-t", &self.table, "-D", ch, "-j", &self.chain])?;
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    fn delete_chain(&self, ip6: bool) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        // Only attempt if the chain exists
        if self.check_cmd(bin, &["-t", &self.table, "-S", &self.chain]) {
            // Flush then delete
            let _ = self.run_cmd(bin, &["-t", &self.table, "-F", &self.chain]);
            let _ = self.run_cmd(bin, &["-t", &self.table, "-X", &self.chain]);
        }
        Ok(())
    }

    fn list_ipsets(&self) -> Result<Vec<String>> {
        let out = self.run_cmd_capture_stdout(&self.ipset_bin, &["list", "-name"])?;
        Ok(out
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn destroy_sets_with_prefix(&self, prefix: &str) -> Result<()> {
        let Ok(sets) = self.list_ipsets() else { return Ok(()); };
        let mut targets: Vec<String> = Vec::new();
        for s in sets {
            if s == prefix || s.starts_with(&format!("{}-", prefix)) {
                targets.push(s);
            }
        }
        for name in targets {
            // Best-effort: flush then destroy; log warnings but continue
            if let Err(e) = self.run_cmd(&self.ipset_bin, &["flush", &name]) { warn!("failed to flush ipset {}: {}", name, e); }
            if let Err(e) = self.run_cmd(&self.ipset_bin, &["destroy", &name]) { warn!("failed to destroy ipset {}: {}", name, e); }
        }
        Ok(())
    }

    fn ensure_jump_from_chains(&self, ip6: bool, chains: &[String]) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        for ch in chains {
            if !self.check_cmd(bin, &["-t", &self.table, "-C", ch, "-j", &self.chain]) {
                self.run_cmd(bin, &["-t", &self.table, "-I", ch, "-j", &self.chain])?;
            }
        }
        Ok(())
    }

    fn ensure_set_match_rule(&self, ip6: bool) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        let action = match self.deny_action {
            DenyAction::Drop => "DROP",
            DenyAction::Reject => "REJECT",
            DenyAction::Tarpit => {
                warn!("TARPIT not supported by default; falling back to DROP");
                "DROP"
            }
            DenyAction::Log => {
                warn!("LOG action does not block; falling back to DROP for enforcement");
                "DROP"
            }
        };
        // We no longer match a single monolithic set here; rules will target per-origin sets.
        // The chain should be present and jumped into from configured chains.
        // Per-origin set rules are installed lazily when origins are observed.
        Ok(())
    }

    fn ip_version_for_value(value: &str) -> Option<IpVersion> {
        if value.contains(':') { Some(IpVersion::V6) } else if value.contains('.') { Some(IpVersion::V4) } else { None }
    }

    fn ipset_add(&self, set_name: &str, value: &str) -> Result<()> {
        self.run_cmd(&self.ipset_bin, &["add", set_name, value, "-exist"])
    }

    fn ipset_del(&self, set_name: &str, value: &str) -> Result<()> {
        self.run_cmd(&self.ipset_bin, &["del", set_name, value, "-exist"])
    }

    fn ipset_restore(&self, script: &str) -> Result<()> {
        let mut child = Command::new(&self.ipset_bin)
            .arg("restore")
            .arg("-exist")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn ipset restore")?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .context("failed to write to ipset restore stdin")?;
        }
        let output = child.wait_with_output().context("failed to wait for ipset restore")?;
        if !output.status.success() {
            return Err(anyhow!(
                "ipset restore failed: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl FirewallBackend for IptablesBackend {
    async fn init(&mut self) -> Result<()> {
        self.ensure_binaries()?;
        // Ensure ipset sets
        if self.ipv4 { self.ensure_ipset(&self.set_v4, "inet")?; }
        if self.ipv6 { self.ensure_ipset(&self.set_v6, "inet6")?; }

        // Ensure chains and rules
        if self.ipv4 {
            self.ensure_chain_exists(false)?;
            if !self.injection_chains_v4.is_empty() {
                self.ensure_jump_from_chains(false, &self.injection_chains_v4)?;
            }
        }
        if self.ipv6 {
            self.ensure_chain_exists(true)?;
            if !self.injection_chains_v6.is_empty() {
                self.ensure_jump_from_chains(true, &self.injection_chains_v6)?;
            }
        }

        info!(
            "iptables backend initialized (table={}, chain={}, set_v4={}, set_v6={}, action={:?}, v4_chains={:?}, v6_chains={:?})",
            self.table, self.chain, self.set_v4, self.set_v6, self.deny_action, self.injection_chains_v4, self.injection_chains_v6
        );
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("iptables backend shutdown: removing jumps, deleting chain, and destroying ipsets");
        // Remove jump rules first to allow chain deletion
        if self.ipv4 && !self.injection_chains_v4.is_empty() {
            self.remove_jump_from_chains(false, &self.injection_chains_v4)?;
        }
        if self.ipv6 && !self.injection_chains_v6.is_empty() {
            self.remove_jump_from_chains(true, &self.injection_chains_v6)?;
        }

        // Delete the custom chain
        if self.ipv4 { self.delete_chain(false)?; }
        if self.ipv6 { self.delete_chain(true)?; }

        // Destroy sets (base and per-origin sets)
        if self.ipv4 { self.destroy_sets_with_prefix(&self.set_v4)?; }
        if self.ipv6 { self.destroy_sets_with_prefix(&self.set_v6)?; }

        Ok(())
    }

    async fn add(&mut self, decision: &Decision) -> Result<()> {
        debug!("iptables add: {:?}", decision);
        if let Some(ipver) = Self::ip_version_for_value(&decision.value) {
            let origin = decision.origin.as_deref().unwrap_or("default").to_string();
            match ipver {
                IpVersion::V4 if self.ipv4 => self.pending_add_v4.push(format!("{}:{}", origin, decision.value)),
                IpVersion::V6 if self.ipv6 => self.pending_add_v6.push(format!("{}:{}", origin, decision.value)),
                _ => {}
            }
            crate::metrics::DECISIONS_BY_ORIGIN.with_label_values(&[&origin, "add"]).inc();
        } else {
            warn!("decision value not an IP/CIDR: {}", decision.value);
        }
        Ok(())
    }

    async fn delete(&mut self, decision: &Decision) -> Result<()> {
        debug!("iptables del: {:?}", decision);
        if let Some(ipver) = Self::ip_version_for_value(&decision.value) {
            let origin = decision.origin.as_deref().unwrap_or("default").to_string();
            match ipver {
                IpVersion::V4 if self.ipv4 => self.pending_del_v4.push(format!("{}:{}", origin, decision.value)),
                IpVersion::V6 if self.ipv6 => self.pending_del_v6.push(format!("{}:{}", origin, decision.value)),
                _ => {}
            }
            crate::metrics::DECISIONS_BY_ORIGIN.with_label_values(&[&origin, "del"]).inc();
        }
        Ok(())
    }

    async fn commit(&mut self) -> Result<()> {
        debug!("iptables commit");
        let no_work = self.pending_add_v4.is_empty()
            && self.pending_add_v6.is_empty()
            && self.pending_del_v4.is_empty()
            && self.pending_del_v6.is_empty();
        if no_work { return Ok(()); }

        let mut script = String::new();
        // ensure per-origin sets and chain rules for any origin encountered in this batch
        {
            use std::collections::HashSet;
            let mut origins_v4: HashSet<&str> = HashSet::new();
            let mut origins_v6: HashSet<&str> = HashSet::new();
            for s in self.pending_add_v4.iter().chain(self.pending_del_v4.iter()) {
                if let Some((origin, _)) = s.split_once(':') { origins_v4.insert(origin); }
            }
            for s in self.pending_add_v6.iter().chain(self.pending_del_v6.iter()) {
                if let Some((origin, _)) = s.split_once(':') { origins_v6.insert(origin); }
            }
            for o in origins_v4 { ensure_origin_set_and_rule(self, o, false)?; }
            for o in origins_v6 { ensure_origin_set_and_rule(self, o, true)?; }
        }
        // We maintain per-origin sets. Each pending entry is encoded as "origin:value".
        fn build_family_script(entries: &Vec<String>, set_prefix: &str, is_add: bool) -> String {
            let mut s = String::new();
            for item in entries {
                if let Some((origin, value)) = item.split_once(':') {
                    let set_name = format!("{}-{}", set_prefix, origin);
                    let op = if is_add { "add" } else { "del" };
                    s.push_str(&format!("{} {} {}\n", op, set_name, value));
                }
            }
            s
        }

        // deletions first (v4, v6)
        script.push_str(&build_family_script(&self.pending_del_v4, &self.set_v4, false));
        script.push_str(&build_family_script(&self.pending_del_v6, &self.set_v6, false));
        // additions
        script.push_str(&build_family_script(&self.pending_add_v4, &self.set_v4, true));
        script.push_str(&build_family_script(&self.pending_add_v6, &self.set_v6, true));

        // Try restore
        match self.ipset_restore(&script) {
            Ok(()) => {
                self.pending_add_v4.clear();
                self.pending_add_v6.clear();
                self.pending_del_v4.clear();
                self.pending_del_v6.clear();
                Ok(())
            }
            Err(err) => {
                // Keep queues for retry on next commit
                Err(err)
            }
        }
    }

}

/// Public helper to collect iptables metrics used by the metrics server.
pub fn collect_metrics_from_save_and_ipset(cfg: &IptablesMetricsConfig) -> Result<(), ()> {
    // v4
    if let Ok(out) = Command::new(&cfg.iptables_save_bin).args(["-c", "-t", "filter"]).output() {
        if out.status.success() {
            parse_and_update(std::str::from_utf8(&out.stdout).unwrap_or(""), &cfg.chain, &cfg.set_v4_prefix, "ipv4");
        }
    }
    // v6
    if let Ok(out) = Command::new(&cfg.ip6tables_save_bin).args(["-c", "-t", "filter"]).output() {
        if out.status.success() {
            parse_and_update(std::str::from_utf8(&out.stdout).unwrap_or(""), &cfg.chain, &cfg.set_v6_prefix, "ipv6");
        }
    }
    // banned IPs per set
    if let Ok(out) = Command::new(&cfg.ipset_bin).args(["list", "-name"]).output() {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let set_name = line.trim();
                if set_name.is_empty() { continue; }
                let (ip_type, prefix) = if set_name.starts_with(&cfg.set_v4_prefix) { ("ipv4", &cfg.set_v4_prefix) } else if set_name.starts_with(&cfg.set_v6_prefix) { ("ipv6", &cfg.set_v6_prefix) } else { continue };
                let origin = set_name.strip_prefix(&format!("{}-", prefix)).unwrap_or("");
                if origin.is_empty() { continue; }
                if let Ok(det) = Command::new(&cfg.ipset_bin).args(["list", set_name]).output() {
                    if det.status.success() {
                        let details = String::from_utf8_lossy(&det.stdout);
                        let mut count: Option<u64> = None;
                        for l in details.lines() {
                            if let Some(rest) = l.trim().strip_prefix("Number of entries: ") {
                                if let Ok(n) = rest.trim().parse::<u64>() { count = Some(n); break; }
                            }
                        }
                        if let Some(n) = count { metrics::FW_BOUNCER_BANNED_IPS.with_label_values(&[origin, ip_type]).set(n as f64); }
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_and_update(save_output: &str, chain: &str, set_prefix: &str, ip_type: &str) {
    let mut processed_packets: u64 = 0;
    let mut processed_bytes: u64 = 0;
    use std::borrow::Cow;
    for line in save_output.lines() {
        let l = line.trim();
        if l.is_empty() { continue; }
        if let Some(bracket) = l.strip_prefix('[') {
            let mut parts = bracket.splitn(2, ']');
            if let Some(counters) = parts.next() {
                let mut nums = counters.split(':');
                let packets = nums.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let bytes = nums.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                if l.contains(&format!("-j {}", chain)) {
                    processed_packets = processed_packets.saturating_add(packets);
                    processed_bytes = processed_bytes.saturating_add(bytes);
                }
                if l.contains("--match-set") {
                    let after = match l.split_once("--match-set") { Some((_, a)) => a, None => continue };
                    let set_name = after.split_whitespace().next().unwrap_or("");
                    if let Some(rest) = set_name.strip_prefix(set_prefix) {
                        let rest = rest.strip_prefix('-').unwrap_or(rest);
                        if !rest.is_empty() {
                            let origin: Cow<str> = Cow::from(rest);
                            metrics::FW_BOUNCER_DROPPED_PACKETS.with_label_values(&[&origin, ip_type]).set(packets as f64);
                            metrics::FW_BOUNCER_DROPPED_BYTES.with_label_values(&[&origin, ip_type]).set(bytes as f64);
                        }
                    }
                }
            }
        }
    }
    metrics::FW_BOUNCER_PROCESSED_PACKETS.with_label_values(&[ip_type]).set(processed_packets as f64);
    metrics::FW_BOUNCER_PROCESSED_BYTES.with_label_values(&[ip_type]).set(processed_bytes as f64);
}

pub struct IptablesMetricsBackend {
    pub cfg: IptablesMetricsConfig,
}

#[async_trait::async_trait]
impl BackendMetricsCollector for IptablesMetricsBackend {
    async fn collect_metrics(&self) {
        let _ = collect_metrics_from_save_and_ipset(&self.cfg);
    }
}

impl IptablesMetricsBackend {
    pub fn from_config(cfg: &crate::config::Config) -> Self {
        let ic = cfg.iptables.as_ref().expect("iptables config present");
        let mc = IptablesMetricsConfig{
            chain: ic.chain.clone().unwrap_or_else(|| "CROWDSEC_CHAIN".to_string()),
            set_v4_prefix: ic.set_name_v4.clone().unwrap_or_else(|| "crowdsec-blacklist".to_string()),
            set_v6_prefix: ic.set_name_v6.clone().unwrap_or_else(|| "crowdsec6-blacklist".to_string()),
            iptables_save_bin: ic.iptables_save_path.clone().unwrap_or_else(|| "iptables-save".to_string()),
            ip6tables_save_bin: ic.ip6tables_save_path.clone().unwrap_or_else(|| "ip6tables-save".to_string()),
            ipset_bin: ic.ipset_path.clone().unwrap_or_else(|| "ipset".to_string()),
        };
        Self { cfg: mc }
    }
}

#[derive(Copy, Clone, Debug)]
enum IpVersion { V4, V6 }

fn map_set_type_to_ipset(set_type: &str) -> String {
    match set_type.to_lowercase().as_str() {
        "nethash" => "hash:net".to_string(),
        other => other.to_string(),
    }
}

fn ensure_origin_set_and_rule(
    backend: &IptablesBackend,
    origin: &str,
    ip6: bool,
) -> Result<()> {
    // Create per-origin set, and ensure a rule in CROWDSEC_CHAIN that matches this set
    let family = if ip6 { "inet6" } else { "inet" };
    let set_name = if ip6 { format!("{}-{}", backend.set_v6, origin) } else { format!("{}-{}", backend.set_v4, origin) };
    backend.run_cmd(&backend.ipset_bin, &["create", &set_name, &backend.set_type, "family", family, "maxelem", &backend.set_size.to_string(), "-exist"])?;

    let bin = if ip6 { &backend.ip6tables_bin } else { &backend.iptables_bin };
    let action = match backend.deny_action {
        DenyAction::Drop => "DROP",
        DenyAction::Reject => "REJECT",
        DenyAction::Tarpit => "DROP",
        DenyAction::Log => "DROP",
    };
    let check = [
        "-t", &backend.table, "-C", &backend.chain, "-m", "set", "--match-set", &set_name, "src", "-j", action,
    ];
    if !backend.check_cmd(bin, &check) {
        let add = [
            "-t", &backend.table, "-A", &backend.chain, "-m", "set", "--match-set", &set_name, "src", "-j", action,
        ];
        backend.run_cmd(bin, &add)?;
    }
    Ok(())
}


