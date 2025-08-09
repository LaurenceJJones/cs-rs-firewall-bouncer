use crate::config::Config;
use anyhow::{Context, Result};
use log::{debug, warn, info};
use serde::Deserialize;
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Deserialize)]
pub struct Decision {
    pub id: Option<u64>,
    #[serde(rename = "type")] 
    pub decision_type: Option<String>,
    pub uuid: Option<String>,
    pub value: String,
    pub duration: Option<String>,
    pub until: Option<String>,
    pub origin: Option<String>,
    pub scenario: Option<String>,
    pub scope: Option<String>,
    pub simulated: Option<bool>,
}

#[derive(Debug)]
pub struct StreamBatch {
    pub new: Vec<Decision>,
    pub deleted: Vec<Decision>,
}

pub struct Bouncer {
    client: reqwest::Client,
    url: String,
    api_key: String,
    update_every: Duration,
    startup: bool,
    ignore_simulated: bool,
    supported_types: Vec<String>,
    scopes_filter: Option<Vec<String>>,
    types_filter: Option<Vec<String>>,
}

impl Bouncer {
    pub fn new_from_config(cfg: &Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("cs-firewall-bouncer-rs/0.1")
            .build()
            .context("failed building HTTP client")?;
        Ok(Self {
            client,
            url: cfg.api.url.clone(),
            api_key: cfg.api.api_key.clone(),
            update_every: cfg.api.update_frequency,
            startup: true,
            ignore_simulated: cfg.ignore_simulated_decisions.unwrap_or(true),
            supported_types: cfg
                .supported_decisions
                .clone()
                .unwrap_or_else(|| vec!["ban".to_string()])
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            scopes_filter: cfg.api.scopes.clone(),
            types_filter: cfg.api.types.clone(),
        })
    }

    pub fn run(&mut self) -> UnboundedReceiver<StreamBatch> {
        let (tx, rx) = mpsc::unbounded_channel();
        let client = self.client.clone();
        let url = self.url.clone();
        let api_key = self.api_key.clone();
        let update_every = self.update_every;
        let mut startup = self.startup;

        let supported_types = self.supported_types.clone();
        let ignore_simulated = self.ignore_simulated;
        let scopes_filter = self.scopes_filter.clone();
        let types_filter = self.types_filter.clone();
        tokio::spawn(async move {
            info!(
                "decision stream: base_url={} interval={}s startup={} scopes={:?} types={:?}",
                url,
                update_every.as_secs(),
                startup,
                scopes_filter,
                types_filter
            );
            let mut backoff = Duration::from_millis(0);
            let mut first = true;
            loop {
                if !first {
                    sleep(update_every + backoff).await;
                }
                first = false;

                match fetch_decisions(&client, &url, &api_key, startup, scopes_filter.clone(), types_filter.clone()).await {
                    Ok(mut batch) => {
                        crate::metrics::API_CALLS_TOTAL.inc();
                        // filter by simulation and supported types
                        batch.new.retain(|d| should_accept(&supported_types, ignore_simulated, d));
                        batch.deleted.retain(|d| should_accept(&supported_types, ignore_simulated, d));
                        crate::metrics::DECISIONS_NEW_TOTAL.inc_by(batch.new.len() as u64);
                        crate::metrics::DECISIONS_DELETED_TOTAL.inc_by(batch.deleted.len() as u64);
                        let _ = tx.send(batch);
                        backoff = Duration::from_millis(0);
                    }
                    Err(e) => {
                        crate::metrics::API_ERRORS_TOTAL.inc();
                        warn!("API error: {e:?}");
                        // Exponential backoff up to 30s
                        backoff = if backoff.is_zero() { Duration::from_secs(1) } else { (backoff * 2).min(Duration::from_secs(30)) };
                    }
                }
                startup = false;
            }
        });

        rx
    }
}

async fn fetch_decisions(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    startup: bool,
    scopes: Option<Vec<String>>,
    types: Option<Vec<String>>,
) -> Result<StreamBatch> {
    let mut url = format!("{}/v1/decisions/stream?startup={}", base_url.trim_end_matches('/'), startup);
    if let Some(scopes) = scopes.as_ref() {
        if !scopes.is_empty() {
            url.push_str("&scopes=");
            url.push_str(&urlencode_list(scopes));
        }
    }
    if let Some(types) = types.as_ref() {
        if !types.is_empty() {
            url.push_str("&types=");
            url.push_str(&urlencode_list(types));
        }
    }
    let resp = client
        .get(url)
        .header("X-Api-Key", api_key)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("HTTP request failed")?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("unexpected status: {}", status);
    }
    #[derive(Deserialize)]
    struct StreamResp {
        #[serde(default, deserialize_with = "empty_vec_if_null")]
        new: Vec<Decision>,
        #[serde(default, deserialize_with = "empty_vec_if_null")]
        deleted: Vec<Decision>,
    }
    let body: StreamResp = resp.json().await.context("invalid JSON from API")?;
    debug!("fetched: new={}, deleted={}", body.new.len(), body.deleted.len());
    Ok(StreamBatch { new: body.new, deleted: body.deleted })
}

fn should_accept(supported: &[String], ignore_simulated: bool, d: &Decision) -> bool {
    if ignore_simulated && d.simulated.unwrap_or(false) { return false; }
    match d.decision_type.as_ref() {
        Some(t) => supported.contains(&t.to_lowercase()),
        None => true,
    }
}

fn urlencode_list(values: &[String]) -> String {
    values
        .iter()
        .map(|v| urlencoding::encode(v).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn empty_vec_if_null<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt = Option::<Vec<T>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}


