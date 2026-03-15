use anyhow::{Result, anyhow, bail};
use mullvad_daita_controller::{config::ParsedConfig, killswitch};
use std::env;
use std::path::PathBuf;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Clone, Debug)]
struct RuntimeConfig {
    killswitch_enabled: bool,
    interface_name: String,
    config_file: PathBuf,
}

impl RuntimeConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            killswitch_enabled: parse_bool_env("KILLSWITCH_ENABLED", false)?,
            interface_name: env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string()),
            config_file: PathBuf::from(
                env::var("WG_CONFIG_FILE").unwrap_or_else(|_| "/etc/wireguard/wg0.conf".into()),
            ),
        })
    }
}

fn parse_bool_env(key: &str, default: bool) -> Result<bool> {
    match env::var(key) {
        Ok(value) => match value.as_str() {
            "true" | "TRUE" | "1" | "yes" | "YES" => Ok(true),
            "false" | "FALSE" | "0" | "no" | "NO" => Ok(false),
            _ => bail!("{key} must be true or false"),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow!("failed to read {key}: {error}")),
    }
}

async fn wait_for_signal() -> Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigint.recv() => {
            log::info!("received SIGINT");
        }
        _ = sigterm.recv() => {
            log::info!("received SIGTERM");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let runtime = RuntimeConfig::from_env()?;
    let config = ParsedConfig::from_file(&runtime.config_file)?;

    log::info!(
        "starting kill switch harness with interface {} and config {}",
        runtime.interface_name,
        runtime.config_file.display()
    );

    if let Err(error) = async {
        if runtime.killswitch_enabled {
            killswitch::install(&runtime.interface_name, config.entry_peer.endpoint.ip())?;
        }
        wait_for_signal().await
    }
    .await
    {
        killswitch::remove_all();
        return Err(error);
    }

    killswitch::remove_all();
    Ok(())
}
