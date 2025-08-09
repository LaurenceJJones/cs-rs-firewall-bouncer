use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen_addr")]
    pub listen_addr: String,
}

fn default_metrics_listen_addr() -> String {"127.0.0.1:6060".to_string()}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct ApiConfig {
    #[serde(rename = "api_url", alias = "api-url")]
    pub url: String,
    #[serde(rename = "api_key", alias = "api-key")]
    pub api_key: String,
    #[serde(
        default = "default_update_frequency",
        with = "humantime_serde",
        alias = "update-frequency",
        alias = "update_frequency"
    )]
    pub update_frequency: Duration,
    /// Capacity of the in-memory decision stream buffer. When full, the API task will
    /// apply backpressure and wait for the consumer to catch up.
    #[serde(
        default = "default_stream_buffer",
        alias = "stream-buffer",
        alias = "channel-capacity",
        alias = "channel_capacity"
    )]
    pub stream_buffer: usize,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,    // optional request filter scopes
    #[serde(default)]
    pub types: Option<Vec<String>>,     // optional request filter types
}

fn default_update_frequency() -> Duration { Duration::from_secs(10) }
fn default_stream_buffer() -> usize { 128 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct IptablesConfig {
    #[serde(default)]
    pub log_prefix: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub set_name_v4: Option<String>,
    #[serde(default)]
    pub set_name_v6: Option<String>,
    #[serde(default)]
    pub set_type: Option<String>,
    #[serde(default)]
    pub set_size: Option<u32>,
    #[serde(default)]
    pub deny_action: Option<DenyAction>,
    #[serde(default)]
    pub iptables_path: Option<String>,
    #[serde(default)]
    pub ip6tables_path: Option<String>,
    #[serde(default)]
    pub iptables_save_path: Option<String>,
    #[serde(default)]
    pub ip6tables_save_path: Option<String>,
    #[serde(default)]
    pub ipset_path: Option<String>,
    #[serde(default, rename = "chains", alias = "iptables_chains", alias = "iptables-chains")]
    pub chains: Option<Vec<String>>,
    #[serde(default, rename = "v4_chains", alias = "iptables_v4_chains", alias = "iptables-v4-chains")]
    pub v4_chains: Option<Vec<String>>,
    #[serde(default, rename = "v6_chains", alias = "iptables_v6_chains", alias = "iptables-v6-chains")]
    pub v6_chains: Option<Vec<String>>,
}

fn default_ipv4() -> bool { true }
fn default_ipv6() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct NftablesConfig {
    #[serde(default)]
    pub table_family: Option<String>,
    #[serde(default)]
    pub table_name: Option<String>,
    #[serde(default)]
    pub chain_name: Option<String>,
    #[serde(default)]
    pub set_name_v4: Option<String>,
    #[serde(default)]
    pub set_name_v6: Option<String>,
    #[serde(default = "default_ipv4")] 
    pub ipv4: bool,
    #[serde(default = "default_ipv6")] 
    pub ipv6: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct PfConfig {
    #[serde(default)]
    pub anchor: Option<String>,
    #[serde(default)]
    pub table_v4: Option<String>,
    #[serde(default)]
    pub table_v6: Option<String>,
    #[serde(default = "default_ipv4")] 
    pub ipv4: bool,
    #[serde(default = "default_ipv6")] 
    pub ipv6: bool,
    #[serde(default)]
    pub pfctl_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub enum Mode {
    #[serde(rename = "iptables")]
    Iptables,
    #[serde(rename = "nftables")]
    Nftables,
    #[serde(rename = "pf")]
    Pf,
    #[serde(rename = "dry-run")]
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")] 
pub enum DenyAction {
    Drop,
    Reject,
    Tarpit,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")] 
pub struct Config {
    pub mode: Mode, // iptables | nftables | pf | dry-run
    #[serde(flatten)]
    pub api: ApiConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub ipv4: Option<bool>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default)]
    pub iptables: Option<IptablesConfig>,
    // Chain injection configuration (backwards compatible with Go bouncer)
    // If v4/v6 chains are not set, they inherit from iptables_chains.
    #[serde(default, rename = "iptables_v4_chains", alias = "iptables-v4-chains", alias = "iptables-v4_chains")]
    pub iptables_v4_chains: Option<Vec<String>>,
    #[serde(default, rename = "iptables_v6_chains", alias = "iptables-v6-chains", alias = "iptables-v6_chains")]
    pub iptables_v6_chains: Option<Vec<String>>,
    #[serde(default, rename = "iptables_chains", alias = "iptables-chains", alias = "iptables_chains")]
    pub iptables_chains: Option<Vec<String>>,
    #[serde(default)]
    pub nftables: Option<NftablesConfig>,
    #[serde(default)]
    pub pf: Option<PfConfig>,
    #[serde(default)]
    pub supported_decisions: Option<Vec<String>>,
    #[serde(default)]
    pub ignore_simulated_decisions: Option<bool>,
}

impl Config {
    pub fn load_with_local(path: &Path) -> Result<Self> {
        let base_yaml = Self::read_yaml_value(path)
            .with_context(|| format!("failed reading config file: {}", path.display()))?;
        let local_path = Self::derive_local_path(path);
        let merged_yaml = if local_path.exists() {
            let local_yaml = Self::read_yaml_value(&local_path)
                .with_context(|| format!("failed reading local override: {}", local_path.display()))?;
            merge_yaml(base_yaml, local_yaml)
        } else {
            base_yaml
        };
        // Support both flattened and nested api: {...} sections by flattening if necessary
        let merged_yaml = flatten_api_section(merged_yaml);
        // Apply compatibility transforms for Go bouncer YAML
        let merged_yaml = compat_go_yaml(merged_yaml);
        let mut cfg: Self = serde_yaml::from_value(merged_yaml)?;
        cfg.apply_defaults_in_place();
        Ok(cfg)
    }

    fn derive_local_path(path: &Path) -> PathBuf {
        let mut p = PathBuf::from(path);
        let file_name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let local_name = format!("{}.local", file_name);
        p.set_file_name(local_name);
        p
    }

    fn read_yaml_value(path: &Path) -> Result<YamlValue> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let val: YamlValue = serde_yaml::from_str(&data)
            .with_context(|| format!("cannot parse yaml {}", path.display()))?;
        Ok(val)
    }
}
impl Config {
    fn apply_defaults_in_place(&mut self) {
        // Global defaults
        if self.supported_decisions.is_none() {
            self.supported_decisions = Some(vec!["ban".to_string()]);
        }
        if self.ignore_simulated_decisions.is_none() {
            self.ignore_simulated_decisions = Some(true);
        }
        if self.ipv4.is_none() { self.ipv4 = Some(true); }
        if self.ipv6.is_none() { self.ipv6 = Some(true); }

        // iptables defaults (backend-level flags used as fallback if global not set)
        if let Some(ipt) = &mut self.iptables {
            if ipt.table.is_none() { ipt.table = Some("filter".to_string()); }
            if ipt.chain.is_none() { ipt.chain = Some("CROWDSEC_CHAIN".to_string()); }
            if ipt.set_name_v4.is_none() { ipt.set_name_v4 = Some("crowdsec-blacklist".to_string()); }
            if ipt.set_name_v6.is_none() { ipt.set_name_v6 = Some("crowdsec6-blacklist".to_string()); }
            if ipt.set_type.is_none() { ipt.set_type = Some("nethash".to_string()); }
            if ipt.set_size.is_none() { ipt.set_size = Some(131072); }
            if ipt.deny_action.is_none() { ipt.deny_action = Some(DenyAction::Drop); }
        } else {
            self.iptables = Some(IptablesConfig {
                log_prefix: None,
                table: Some("filter".to_string()),
                chain: Some("CROWDSEC_CHAIN".to_string()),
                set_name_v4: Some("crowdsec-blacklist".to_string()),
                set_name_v6: Some("crowdsec6-blacklist".to_string()),
                set_type: Some("nethash".to_string()),
                set_size: Some(131072),
                deny_action: Some(DenyAction::Drop),
                iptables_path: None,
                ip6tables_path: None,
                iptables_save_path: None,
                ip6tables_save_path: None,
                ipset_path: None,
                chains: None,
                v4_chains: None,
                v6_chains: None,
            });
        }

        // nftables defaults
        if let Some(nft) = &mut self.nftables {
            if nft.table_family.is_none() { nft.table_family = Some("inet".to_string()); }
            if nft.table_name.is_none() { nft.table_name = Some("crowdsec".to_string()); }
            if nft.chain_name.is_none() { nft.chain_name = Some("crowdsec".to_string()); }
            if nft.set_name_v4.is_none() { nft.set_name_v4 = Some("crowdsec-blacklist".to_string()); }
            if nft.set_name_v6.is_none() { nft.set_name_v6 = Some("crowdsec6-blacklist".to_string()); }
        } else {
            self.nftables = Some(NftablesConfig {
                table_family: Some("inet".to_string()),
                table_name: Some("crowdsec".to_string()),
                chain_name: Some("crowdsec".to_string()),
                set_name_v4: Some("crowdsec-blacklist".to_string()),
                set_name_v6: Some("crowdsec6-blacklist".to_string()),
                ipv4: true,
                ipv6: true,
            });
        }

        // pf defaults
        if let Some(pf) = &mut self.pf {
            if pf.anchor.is_none() { pf.anchor = Some("crowdsec/*".to_string()); }
            if pf.table_v4.is_none() { pf.table_v4 = Some("crowdsec_blacklist".to_string()); }
            if pf.table_v6.is_none() { pf.table_v6 = Some("crowdsec6_blacklist".to_string()); }
        } else {
            self.pf = Some(PfConfig {
                anchor: Some("crowdsec/*".to_string()),
                table_v4: Some("crowdsec_blacklist".to_string()),
                table_v6: Some("crowdsec6_blacklist".to_string()),
                ipv4: true,
                ipv6: true,
                pfctl_path: None,
            });
        }
    }
}


fn merge_yaml(base: YamlValue, overlay: YamlValue) -> YamlValue {
    match (base, overlay) {
        (YamlValue::Mapping(mut a), YamlValue::Mapping(b)) => {
            for (k, v_b) in b {
                match a.remove(&k) {
                    Some(v_a) => {
                        a.insert(k, merge_yaml(v_a, v_b));
                    }
                    None => {
                        a.insert(k, v_b);
                    }
                }
            }
            YamlValue::Mapping(a)
        }
        (_, over) => over,
    }
}

// If the YAML has an `api` mapping, lift its keys up to the top level to match #[serde(flatten)]
fn flatten_api_section(root: YamlValue) -> YamlValue {
    use serde_yaml::Value::{Mapping, String as YString};
    let api_key = YString("api".to_string());
    if let Mapping(mut m) = root {
        if let Some(Mapping(api)) = m.remove(&api_key) {
            for (k, v) in api.into_iter() {
                m.insert(k, v);
            }
        }
        Mapping(m)
    } else {
        root
    }
}

// Transform keys used by the Go bouncer YAML into our schema to maintain drop-in compatibility
fn compat_go_yaml(root: YamlValue) -> YamlValue {
    use serde_yaml::Value::{Mapping, String as YString};
    let mut root = match root {
        Mapping(m) => m,
        other => return other,
    };

    // supported_decisions_types -> supported_decisions
    let key_old = YString("supported_decisions_types".to_string());
    if let Some(v) = root.remove(&key_old) {
        root.insert(YString("supported_decisions".to_string()), v);
    }

    // prometheus.{enabled, listen_addr, listen_port} -> metrics.{enabled, listen_addr}
    if let Some(serde_yaml::Value::Mapping(prom)) = root.remove(&YString("prometheus".to_string())) {
        let enabled = prom
            .get(&YString("enabled".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let addr = prom
            .get(&YString("listen_addr".to_string()))
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1");
        let port = prom
            .get(&YString("listen_port".to_string()))
            .and_then(|v| v.as_i64())
            .unwrap_or(6060);
        let mut mm = serde_yaml::Mapping::new();
        mm.insert(YString("enabled".to_string()), serde_yaml::Value::Bool(enabled));
        if enabled {
            let combined = format!("{}:{}", addr, port);
            mm.insert(YString("listen_addr".to_string()), serde_yaml::Value::String(combined));
        }
        root.insert(YString("metrics".to_string()), serde_yaml::Value::Mapping(mm));
    }

    // Stash values we want to map before we mutably borrow the iptables mapping
    let v_blacklists_ipv4 = root.remove(&YString("blacklists_ipv4".to_string()));
    let v_blacklists_ipv6 = root.remove(&YString("blacklists_ipv6".to_string()));
    let v_ipset_type = root.remove(&YString("ipset_type".to_string()));
    let v_deny_action = root.remove(&YString("deny_action".to_string()));
    let v_deny_log_prefix = root.remove(&YString("deny_log_prefix".to_string()));
    let v_disable_ipv6 = root.remove(&YString("disable_ipv6".to_string()));
    let v_iptables_chains = root.remove(&YString("iptables_chains".to_string()));
    let v_iptables_v4_chains = root.remove(&YString("iptables_v4_chains".to_string()));
    let v_iptables_v6_chains = root.remove(&YString("iptables_v6_chains".to_string()));

    // Map Go's disable_ipv6 to our global ipv6 flag when absent
    if let Some(serde_yaml::Value::Bool(b)) = v_disable_ipv6 {
        let want_ipv6 = !b;
        let _ = root.entry(YString("ipv6".to_string())).or_insert(serde_yaml::Value::Bool(want_ipv6));
    }

    // Prepare/ensure iptables mapping exists to receive mapped keys
    let ipt_key = YString("iptables".to_string());
    let ipt_entry = root.entry(ipt_key.clone()).or_insert(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let ipt_map = match ipt_entry {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            // Replace non-mapping with mapping
            *ipt_entry = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
            if let serde_yaml::Value::Mapping(m) = ipt_entry {
                m
            } else {
                unreachable!()
            }
        }
    };

    // Apply stashed mappings into iptables.*
    if let Some(v) = v_blacklists_ipv4 { ipt_map.insert(YString("set_name_v4".to_string()), v); }
    if let Some(v) = v_blacklists_ipv6 { ipt_map.insert(YString("set_name_v6".to_string()), v); }
    if let Some(v) = v_ipset_type { ipt_map.insert(YString("set_type".to_string()), v); }
    if let Some(v) = v_deny_action {
        if !ipt_map.contains_key(&YString("deny_action".to_string())) {
            ipt_map.insert(YString("deny_action".to_string()), v);
        }
    }
    if let Some(v) = v_deny_log_prefix { ipt_map.insert(YString("log_prefix".to_string()), v); }
    if let Some(v) = v_iptables_chains { ipt_map.insert(YString("chains".to_string()), v); }
    if let Some(v) = v_iptables_v4_chains { ipt_map.insert(YString("v4_chains".to_string()), v); }
    if let Some(v) = v_iptables_v6_chains { ipt_map.insert(YString("v6_chains".to_string()), v); }
    // iptables_add_rule_comments is accepted but ignored; no transform needed

    serde_yaml::Value::Mapping(root)
}

