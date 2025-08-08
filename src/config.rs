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
        alias = "update_every"
    )]
    pub update_frequency: Duration,
    #[serde(default)]
    pub startup: bool,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,    // optional request filter scopes
    #[serde(default)]
    pub types: Option<Vec<String>>,     // optional request filter types
}

fn default_update_frequency() -> Duration { Duration::from_secs(2) }

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
    pub input_chain: Option<String>,
    #[serde(default)]
    pub forward_chain: Option<String>,
    #[serde(default)]
    pub extra_chains: Option<Vec<String>>, // additional chains to jump into CROWDSEC_CHAIN
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
    #[serde(default = "default_ipv4")] 
    pub ipv4: bool,
    #[serde(default = "default_ipv6")] 
    pub ipv6: bool,
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
    pub iptables: Option<IptablesConfig>,
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

        // iptables defaults
        if let Some(ipt) = &mut self.iptables {
            if ipt.table.is_none() { ipt.table = Some("filter".to_string()); }
            if ipt.chain.is_none() { ipt.chain = Some("CROWDSEC_CHAIN".to_string()); }
            if ipt.input_chain.is_none() { ipt.input_chain = Some("INPUT".to_string()); }
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
                input_chain: Some("INPUT".to_string()),
                forward_chain: None,
                extra_chains: Some(vec![]),
                set_name_v4: Some("crowdsec-blacklist".to_string()),
                set_name_v6: Some("crowdsec6-blacklist".to_string()),
                set_type: Some("nethash".to_string()),
                set_size: Some(131072),
                deny_action: Some(DenyAction::Drop),
                ipv4: true,
                ipv6: true,
                iptables_path: None,
                ip6tables_path: None,
                iptables_save_path: None,
                ip6tables_save_path: None,
                ipset_path: None,
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
fn flatten_api_section(mut root: YamlValue) -> YamlValue {
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

