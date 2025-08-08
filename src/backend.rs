use crate::api::Decision;
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
// no-op

#[cfg(all(feature = "backends-iptables", target_os = "linux"))]
pub mod iptables;

pub mod factory {
    use super::*;
    use crate::backend::dry_run::DryRunBackend;
    use crate::config::Mode;

    pub async fn create_backend(cfg: &Config) -> Result<Box<dyn FirewallBackend>> {
        match cfg.mode {
            Mode::DryRun => Ok(Box::new(DryRunBackend::new())),
            #[cfg(all(feature = "backends-iptables", target_os = "linux"))]
            Mode::Iptables => Ok(Box::new(crate::backend::iptables::IptablesBackend::new(cfg))),
            #[cfg(all(feature = "backends-nftables", target_os = "linux"))]
            Mode::Nftables => anyhow::bail!("nftables backend not yet implemented"),
            #[cfg(all(feature = "backends-pf", any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
            Mode::Pf => anyhow::bail!("pf backend not yet implemented"),
            #[cfg(not(all(feature = "backends-iptables", target_os = "linux")))]
            Mode::Iptables => anyhow::bail!("iptables mode requested but backend not compiled or not on Linux"),
            #[cfg(not(all(feature = "backends-nftables", target_os = "linux")))]
            Mode::Nftables => anyhow::bail!("nftables mode requested but backend not compiled or not on Linux"),
            #[cfg(not(all(feature = "backends-pf", any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))))]
            Mode::Pf => anyhow::bail!("pf mode requested but backend not compiled or not on BSD"),
        }
    }
}

#[async_trait]
pub trait FirewallBackend: Send + Sync {
    async fn init(&mut self) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    async fn add(&mut self, decision: &Decision) -> Result<()>;
    async fn delete(&mut self, decision: &Decision) -> Result<()>;
    async fn commit(&mut self) -> Result<()>;
}

pub mod dry_run {
    use super::*;
    use log::{debug, info};

    pub struct DryRunBackend {}

    impl DryRunBackend {
        pub fn new() -> Self { Self { } }
    }

    #[async_trait]
    impl FirewallBackend for DryRunBackend {
        async fn init(&mut self) -> Result<()> {
            info!("dry-run backend initialized");
            Ok(())
        }

        async fn shutdown(&mut self) -> Result<()> {
            info!("dry-run backend shutdown");
            Ok(())
        }

        async fn add(&mut self, decision: &Decision) -> Result<()> {
            debug!("add decision: {:?}", decision);
            crate::metrics::DECISIONS_APPLIED_TOTAL.inc();
            Ok(())
        }

        async fn delete(&mut self, decision: &Decision) -> Result<()> {
            debug!("delete decision: {:?}", decision);
            crate::metrics::DECISIONS_REMOVED_TOTAL.inc();
            Ok(())
        }

        async fn commit(&mut self) -> Result<()> {
            debug!("commit");
            Ok(())
        }
    }
}


