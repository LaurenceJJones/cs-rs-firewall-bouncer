#![cfg(all(feature = "backends-iptables", target_os = "linux"))]

use crate::api::Decision;
use crate::backend::FirewallBackend;
use crate::config::{Config, DenyAction};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::io::Write;
use std::process::{Command, Stdio};

pub struct IptablesBackend {
    // binaries
    iptables_bin: String,
    ip6tables_bin: String,
    ipset_bin: String,

    // config
    table: String,
    chain: String,
    input_chain: String,
    forward_chain: Option<String>,
    extra_chains: Vec<String>,
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
        Self {
            iptables_bin: ic.iptables_path.clone().unwrap_or_else(|| "iptables".to_string()),
            ip6tables_bin: ic.ip6tables_path.clone().unwrap_or_else(|| "ip6tables".to_string()),
            ipset_bin: ic.ipset_path.clone().unwrap_or_else(|| "ipset".to_string()),
            table: ic.table.clone().unwrap_or_else(|| "filter".to_string()),
            chain: ic.chain.clone().unwrap_or_else(|| "CROWDSEC".to_string()),
            input_chain: ic.input_chain.clone().unwrap_or_else(|| "INPUT".to_string()),
            forward_chain: ic.forward_chain.clone(),
            extra_chains: ic.extra_chains.clone().unwrap_or_default(),
            set_v4: ic.set_name_v4.clone().unwrap_or_else(|| "crowdsec-blacklist".to_string()),
            set_v6: ic.set_name_v6.clone().unwrap_or_else(|| "crowdsec6-blacklist".to_string()),
            set_type,
            set_size: ic.set_size.unwrap_or(131072),
            deny_action: ic.deny_action.clone().unwrap_or(DenyAction::Drop),
            ipv4: ic.ipv4,
            ipv6: ic.ipv6,
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

    fn ensure_jump_from_input(&self, ip6: bool) -> Result<()> {
        let bin = if ip6 { &self.ip6tables_bin } else { &self.iptables_bin };
        // iptables -t <table> -C <INPUT> -j <chain>
        if !self.check_cmd(bin, &["-t", &self.table, "-C", &self.input_chain, "-j", &self.chain]) {
            // Insert at top
            self.run_cmd(bin, &["-t", &self.table, "-I", &self.input_chain, "-j", &self.chain])?;
        }
        Ok(())
    }

    fn ensure_jump_from_extra_chains(&self, ip6: bool, chains: &[String]) -> Result<()> {
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
            self.ensure_jump_from_input(false)?; 
            if let Some(forward) = &self.forward_chain {
                self.ensure_jump_from_extra_chains(false, &[forward.clone()])?;
            }
            if !self.extra_chains.is_empty() {
                self.ensure_jump_from_extra_chains(false, &self.extra_chains)?;
            }
        }
        if self.ipv6 { 
            self.ensure_chain_exists(true)?; 
            self.ensure_jump_from_input(true)?; 
            if let Some(forward) = &self.forward_chain {
                self.ensure_jump_from_extra_chains(true, &[forward.clone()])?;
            }
            if !self.extra_chains.is_empty() {
                self.ensure_jump_from_extra_chains(true, &self.extra_chains)?;
            }
        }

        info!(
            "iptables backend initialized (table={}, chain={}, set_v4={}, set_v6={}, action={:?})",
            self.table, self.chain, self.set_v4, self.set_v6, self.deny_action
        );
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("iptables backend shutdown");
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


