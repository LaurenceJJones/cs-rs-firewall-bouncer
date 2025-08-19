mod config;
mod api;
mod backend;
mod metrics;
mod usage_metrics;

use std::path::PathBuf;
use clap::{ArgAction, Parser};
use log::{debug, error, info};
use sd_notify::NotifyState;

#[derive(Parser, Debug)]
#[command(name = "cs-firewall-bouncer", version, author, about = "Rust port of CrowdSec firewall bouncer")] 
struct Cli {
    /// Path to configuration file
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: Option<PathBuf>,

    /// Validate config and exit
    #[arg(short = 't', long = "test-config", action = ArgAction::SetTrue)]
    test_config: bool,

    /// Print the merged config and exit
    #[arg(short = 'T', long = "print-config", action = ArgAction::SetTrue)]
    print_config: bool,

    /// Verbose logging
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    let default_level = if cli.verbose > 0 { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level)).init();

    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("/etc/crowdsec/bouncers/cs-firewall-bouncer.yaml"));
    let cfg = match config::Config::load_with_local(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config: {e:?}");
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                eprintln!("\n----- raw config file -----\n{}\n---------------------------\n", raw);
            }
            return Err(e);
        }
    };

    if cli.print_config {
        let yaml = serde_yaml::to_string(&cfg)?;
        println!("{yaml}");
        return Ok(());
    }

    if cli.test_config {
        info!("configuration is valid");
        return Ok(());
    }

    // Initialize backend
    let mut backend = backend::factory::create_backend(&cfg).await?;
    backend.init().await?;

    // Start API client/bouncer
    let mut bouncer = api::Bouncer::new_from_config(&cfg)?;
    let mut decision_rx = bouncer.run(cfg.api.stream_buffer);

    // Prometheus metrics are always registered and collected; if enabled, bind the HTTP listener
    let metrics_guard = if let Some(metrics) = cfg.metrics.as_ref() {
        let collector = crate::backend::factory::create_metrics_collector(&cfg);
        if metrics.enabled {
            Some(tokio::spawn(crate::metrics::serve_metrics(metrics.listen_addr.clone(), collector)))
        } else {
            None
        }
    } else { None };

    // Start periodic usage metrics to LAPI (every 15 minutes)
    let lapi_metrics_guard = {
        let client = reqwest::Client::new();
        let base_url = cfg.api.url.clone();
        let api_key = cfg.api.api_key.clone();
        let version = env!("CARGO_PKG_VERSION").to_string();
        let bouncer_type = "crowdsec-firewall-bouncer".to_string();
        let startup_ts = chrono::Utc::now().timestamp();
        // Prepare optional backend metrics collector to refresh gauges
        let refresh = crate::backend::factory::create_metrics_collector(&cfg);
        Some(tokio::spawn(crate::usage_metrics::start_usage_metrics(
            client,
            base_url,
            api_key,
            version,
            bouncer_type,
            startup_ts,
            std::time::Duration::from_secs(15 * 60),
            refresh,
        )))
    };

    // Notify systemd that we are ready, if running under systemd
    let _ = sd_notify::notify(true, &[NotifyState::Ready]);

    info!("bouncer started; waiting for decisions");

    // Graceful shutdown handling
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let shutdown_tx2 = shutdown_tx.clone();
    let _sig_task = tokio::spawn(async move {
        // Handle Ctrl+C and SIGTERM
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = shutdown_tx2.send(());
    });

    // Main processing loop
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => {
                info!("shutdown signal received");
                break;
            }
            maybe_batch = decision_rx.recv() => {
                match maybe_batch {
                    Some(batch) => {
                        let mut added = 0usize;
                        let mut deleted = 0usize;
                        for d in batch.deleted {
                            backend.delete(&d).await?;
                            deleted += 1;
                        }
                        for d in batch.new {
                            backend.add(&d).await?;
                            added += 1;
                        }
                        backend.commit().await?;
                        crate::metrics::BATCHES_PROCESSED_TOTAL.inc();
                        crate::metrics::DECISIONS_APPLIED_TOTAL.inc_by(added as u64);
                        crate::metrics::DECISIONS_REMOVED_TOTAL.inc_by(deleted as u64);
                        debug!("processed decisions: added={added}, deleted={deleted}");
                    }
                    None => {
                        error!("decision stream ended unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    // Notify systemd that we are stopping and extend the stop timeout window
    let _ = sd_notify::notify(true, &[NotifyState::Stopping]);
    let _ = sd_notify::notify(true, &[NotifyState::ExtendTimeoutUsec(30_000_000u32)]);

    // Best-effort flush of any in-flight operations
    let _ = backend.commit().await;

    backend.shutdown().await?;

    if let Some(handle) = metrics_guard {
        handle.abort();
    }
    if let Some(handle) = lapi_metrics_guard { handle.abort(); }

    // Final watchdog ping to indicate we finished cleanly
    let _ = sd_notify::notify(true, &[NotifyState::Status("exiting".into())]);

    info!("exiting");
    Ok(())
}
