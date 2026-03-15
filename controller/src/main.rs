use anyhow::{Context, Result, anyhow, bail};
use mullvad_daita_controller::config::ParsedConfig;
use mullvad_daita_controller::killswitch;
use std::env;
use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::net::IpAddr;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;
use talpid_tunnel_config_client::request_ephemeral_peer;
use talpid_types::net::wireguard::PrivateKey;
use tokio::signal::unix::{SignalKind, signal};
use tun::AbstractDevice;
use wireguard_go_rs::{LoggingContext, Tunnel, WgLogLevel};

const DAITA_EVENTS_CAPACITY: u32 = 2048;
const DAITA_ACTIONS_CAPACITY: u32 = 1024;

#[derive(Clone, Debug)]
struct RuntimeConfig {
    daita_enabled: bool,
    killswitch_enabled: bool,
    interface_name: String,
    config_file: PathBuf,
}

#[derive(Debug)]
struct DefaultRoute {
    dev: String,
    via: Option<IpAddr>,
}

#[derive(Debug)]
struct RouteRecord {
    family_flag: &'static str,
    cidr: String,
    dev: String,
    via: Option<IpAddr>,
}

#[derive(Debug, Default)]
struct SystemState {
    endpoint_route: Option<RouteRecord>,
    killswitch_installed: bool,
    resolv_conf_backup: Option<String>,
}

struct Controller {
    runtime: RuntimeConfig,
    config: ParsedConfig,
    tunnel: Option<Tunnel>,
    system_state: SystemState,
    post_up_completed: bool,
}

impl RuntimeConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            daita_enabled: parse_bool_env("DAITA_ENABLED", false)?,
            killswitch_enabled: parse_bool_env("KILLSWITCH_ENABLED", false)?,
            interface_name: env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string()),
            config_file: PathBuf::from(
                env::var("WG_CONFIG_FILE").unwrap_or_else(|_| "/etc/wireguard/wg0.conf".into()),
            ),
        })
    }
}

impl Controller {
    async fn new() -> Result<Self> {
        let runtime = RuntimeConfig::from_env()?;
        let config = ParsedConfig::from_file(&runtime.config_file)?;
        Ok(Self {
            runtime,
            config,
            tunnel: None,
            system_state: SystemState::default(),
            post_up_completed: false,
        })
    }

    async fn run(mut self) -> Result<()> {
        if let Err(error) = self.bootstrap().await {
            self.shutdown(true)?;
            return Err(error);
        }

        wait_for_signal().await?;
        self.shutdown(false)
    }

    async fn bootstrap(&mut self) -> Result<()> {
        log::info!(
            "starting tunnel controller with interface {} and config {}",
            self.runtime.interface_name,
            self.runtime.config_file.display()
        );

        self.run_hooks("PreUp", &self.config.hooks.pre_up)?;
        self.start_tunnel()?;
        self.configure_interface()?;
        if self.runtime.daita_enabled {
            self.activate_daita().await?;
        }
        if self.runtime.killswitch_enabled {
            self.install_killswitch()?;
        }
        self.run_hooks("PostUp", &self.config.hooks.post_up)?;
        self.post_up_completed = true;

        if self.runtime.daita_enabled {
            log::info!("DAITA activation completed");
        } else {
            log::info!("tunnel started without DAITA activation");
        }

        Ok(())
    }

    fn start_tunnel(&mut self) -> Result<()> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(&self.runtime.interface_name);
        tun_config.mtu(self.config.mtu);
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|config| {
            #[allow(deprecated)]
            {
                config.packet_information(true);
            }
        });

        let device = tun::create(&tun_config).context("failed to create TUN device")?;
        let actual_name = device
            .tun_name()
            .context("failed to query TUN device name")?;
        if actual_name != self.runtime.interface_name {
            bail!(
                "requested interface {} but kernel created {}",
                self.runtime.interface_name,
                actual_name
            );
        }

        let fd = device.into_raw_fd();
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let settings = self.config.initial_settings()?;
        let tunnel = Tunnel::turn_on(
            self.config.mtu as isize,
            &settings,
            owned_fd,
            Some(wireguard_log_callback),
            0 as LoggingContext,
        )
        .map_err(|error| anyhow!("failed to start wireguard-go tunnel: {error}"))?;

        self.tunnel = Some(tunnel);
        Ok(())
    }

    fn configure_interface(&mut self) -> Result<()> {
        self.configure_endpoint_bypass_route()?;
        self.apply_interface_addresses()?;
        self.apply_link_state()?;
        self.apply_tunnel_routes()?;
        self.apply_dns()?;
        Ok(())
    }

    async fn activate_daita(&mut self) -> Result<()> {
        let config_service = self.config.config_service_ipv4();
        let ephemeral_private_key = PrivateKey::new_from_random();
        let exit_response = request_ephemeral_peer(
            config_service,
            self.config.private_key.public_key(),
            ephemeral_private_key.public_key(),
            false,
            !self.config.is_multihop(),
        )
        .await
        .map_err(|error| anyhow!("failed to request exit ephemeral peer: {error}"))?;

        let (settings, daita_peer_public_key, daita) = if self.config.is_multihop() {
            let entry_only_settings = self.config.entry_hop_config_for_ephemeral_exchange()?;
            self.tunnel
                .as_ref()
                .ok_or_else(|| anyhow!("tunnel is not active"))?
                .set_config(&entry_only_settings)
                .map_err(|error| {
                    anyhow!("failed to reconfigure tunnel for entry ephemeral exchange: {error}")
                })?;

            let entry_response = request_ephemeral_peer(
                config_service,
                self.config.private_key.public_key(),
                ephemeral_private_key.public_key(),
                false,
                true,
            )
            .await
            .map_err(|error| anyhow!("failed to request entry ephemeral peer: {error}"))?;

            let daita = entry_response
                .daita
                .ok_or_else(|| anyhow!("relay config service returned no DAITA settings"))?;
            let settings = self.config.multihop_daita_settings(
                &ephemeral_private_key,
                entry_response.psk.as_ref(),
                exit_response.psk.as_ref(),
            )?;

            (settings, self.config.entry_peer.public_key.clone(), daita)
        } else {
            let daita = exit_response
                .daita
                .ok_or_else(|| anyhow!("relay config service returned no DAITA settings"))?;
            let settings = self
                .config
                .daita_settings(&ephemeral_private_key, exit_response.psk.as_ref())?;

            (settings, self.config.entry_peer.public_key.clone(), daita)
        };

        self.tunnel
            .as_ref()
            .ok_or_else(|| anyhow!("tunnel is not active"))?
            .set_config(&settings)
            .map_err(|error| anyhow!("failed to reconfigure tunnel for DAITA: {error}"))?;

        let machines = daita
            .client_machines
            .into_iter()
            .map(|machine| machine.serialize())
            .collect::<Vec<_>>()
            .join("\n");
        let machines =
            CString::new(machines).context("relay config returned invalid maybenot machines")?;

        self.tunnel
            .as_ref()
            .ok_or_else(|| anyhow!("tunnel is not active"))?
            .activate_daita(
                daita_peer_public_key.as_bytes(),
                &machines,
                daita.max_decoy_frac,
                daita.max_delay_frac,
                DAITA_EVENTS_CAPACITY,
                DAITA_ACTIONS_CAPACITY,
            )
            .map_err(|error| anyhow!("failed to activate DAITA: {error}"))?;

        Ok(())
    }

    fn shutdown(&mut self, startup_failed: bool) -> Result<()> {
        if !startup_failed && self.post_up_completed {
            self.run_hooks("PreDown", &self.config.hooks.pre_down)?;
        }

        self.remove_killswitch()?;
        self.restore_dns()?;
        self.remove_endpoint_bypass_route()?;
        self.stop_tunnel()?;

        if !startup_failed && self.post_up_completed {
            self.run_hooks("PostDown", &self.config.hooks.post_down)?;
        }

        Ok(())
    }

    fn install_killswitch(&mut self) -> Result<()> {
        log::info!("installing container kill switch");
        killswitch::install(
            &self.runtime.interface_name,
            self.config.entry_peer.endpoint.ip(),
        )?;
        self.system_state.killswitch_installed = true;
        Ok(())
    }

    fn remove_killswitch(&mut self) -> Result<()> {
        if !self.system_state.killswitch_installed {
            return Ok(());
        }

        killswitch::remove_all();
        self.system_state.killswitch_installed = false;
        Ok(())
    }

    fn stop_tunnel(&mut self) -> Result<()> {
        if let Some(tunnel) = self.tunnel.take() {
            tunnel
                .turn_off()
                .map_err(|error| anyhow!("failed to stop wireguard-go tunnel: {error}"))?;
        }
        Ok(())
    }

    fn configure_endpoint_bypass_route(&mut self) -> Result<()> {
        let family_flag = match self.config.entry_peer.endpoint.ip() {
            IpAddr::V4(_) => "-4",
            IpAddr::V6(_) => "-6",
        };
        let default_route = read_default_route(family_flag)?;
        let cidr = match self.config.entry_peer.endpoint.ip() {
            IpAddr::V4(ip) => format!("{ip}/32"),
            IpAddr::V6(ip) => format!("{ip}/128"),
        };

        let mut args = vec![
            family_flag.to_string(),
            "route".to_string(),
            "replace".to_string(),
            cidr.clone(),
        ];
        if let Some(via) = default_route.via {
            args.push("via".to_string());
            args.push(via.to_string());
        }
        args.push("dev".to_string());
        args.push(default_route.dev.clone());
        run_ip(args.iter().map(String::as_str))?;

        self.system_state.endpoint_route = Some(RouteRecord {
            family_flag,
            cidr,
            dev: default_route.dev,
            via: default_route.via,
        });
        Ok(())
    }

    fn remove_endpoint_bypass_route(&mut self) -> Result<()> {
        let Some(route) = self.system_state.endpoint_route.take() else {
            return Ok(());
        };

        let mut args = vec![
            route.family_flag.to_string(),
            "route".to_string(),
            "del".to_string(),
            route.cidr,
        ];
        if let Some(via) = route.via {
            args.push("via".to_string());
            args.push(via.to_string());
        }
        args.push("dev".to_string());
        args.push(route.dev);

        if let Err(error) = run_ip(args.iter().map(String::as_str)) {
            log::warn!("failed to remove endpoint bypass route: {error}");
        }
        Ok(())
    }

    fn apply_interface_addresses(&self) -> Result<()> {
        for address in &self.config.addresses {
            run_ip([
                "address",
                "replace",
                &address.to_string(),
                "dev",
                self.runtime.interface_name.as_str(),
            ])?;
        }
        Ok(())
    }

    fn apply_link_state(&self) -> Result<()> {
        run_ip([
            "link",
            "set",
            "dev",
            self.runtime.interface_name.as_str(),
            "mtu",
            &self.config.mtu.to_string(),
            "up",
        ])
    }

    fn apply_tunnel_routes(&self) -> Result<()> {
        for allowed_ip in self.config.effective_allowed_ips() {
            let family_flag = if allowed_ip.is_ipv4() { "-4" } else { "-6" };
            if allowed_ip.prefix() == 0 {
                run_ip([
                    family_flag,
                    "route",
                    "replace",
                    "default",
                    "dev",
                    self.runtime.interface_name.as_str(),
                ])?;
            } else {
                let allowed_ip = allowed_ip.to_string();
                run_ip([
                    family_flag,
                    "route",
                    "replace",
                    allowed_ip.as_str(),
                    "dev",
                    self.runtime.interface_name.as_str(),
                ])?;
            }
        }
        Ok(())
    }

    fn apply_dns(&mut self) -> Result<()> {
        if self.config.dns_servers.is_empty() {
            return Ok(());
        }

        let current = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        self.system_state.resolv_conf_backup = Some(current);
        let new_contents = self
            .config
            .dns_servers
            .iter()
            .map(|server| format!("nameserver {server}\n"))
            .collect::<String>();
        fs::write("/etc/resolv.conf", new_contents).context("failed to write /etc/resolv.conf")?;
        Ok(())
    }

    fn restore_dns(&mut self) -> Result<()> {
        let Some(previous) = self.system_state.resolv_conf_backup.take() else {
            return Ok(());
        };
        fs::write("/etc/resolv.conf", previous).context("failed to restore /etc/resolv.conf")
    }

    fn run_hooks(&self, name: &str, hooks: &[String]) -> Result<()> {
        for hook in hooks {
            let rendered = hook.replace("%i", &self.runtime.interface_name);
            log::info!("running {} hook: {}", name, rendered);
            let status = Command::new("sh")
                .arg("-c")
                .arg(&rendered)
                .status()
                .with_context(|| format!("failed to execute {} hook", name))?;
            if !status.success() {
                bail!("{} hook failed with status {}", name, status);
            }
        }
        Ok(())
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

fn read_default_route(family_flag: &str) -> Result<DefaultRoute> {
    let output = Command::new("ip")
        .arg(family_flag)
        .args(["route", "show", "default"])
        .output()
        .context("failed to query default route")?;
    if !output.status.success() {
        bail!(
            "ip {} route show default failed with status {}",
            family_flag,
            output.status
        );
    }

    let stdout = String::from_utf8(output.stdout).context("default route output was not UTF-8")?;
    let line = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow!("no default route found for {}", family_flag))?;
    let tokens = line.split_whitespace().collect::<Vec<_>>();

    let mut dev = None;
    let mut via = None;
    let mut index = 0usize;
    while index < tokens.len() {
        match tokens[index] {
            "dev" if index + 1 < tokens.len() => {
                dev = Some(tokens[index + 1].to_string());
                index += 1;
            }
            "via" if index + 1 < tokens.len() => {
                via = Some(
                    tokens[index + 1]
                        .parse::<IpAddr>()
                        .with_context(|| format!("invalid gateway IP {}", tokens[index + 1]))?,
                );
                index += 1;
            }
            _ => {}
        }
        index += 1;
    }

    Ok(DefaultRoute {
        dev: dev.ok_or_else(|| anyhow!("no device found in default route output: {}", line))?,
        via,
    })
}

fn run_ip<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();
    let status = Command::new("ip")
        .args(&args)
        .status()
        .with_context(|| format!("failed to execute ip {}", args.join(" ")))?;
    if !status.success() {
        bail!("ip {} failed with status {}", args.join(" "), status);
    }
    Ok(())
}

async fn wait_for_signal() -> Result<()> {
    let mut sigint = signal(SignalKind::interrupt()).context("failed to register SIGINT")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to register SIGTERM")?;
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

unsafe extern "system" fn wireguard_log_callback(
    level: WgLogLevel,
    msg: *const c_char,
    _context: LoggingContext,
) {
    if msg.is_null() {
        return;
    }

    let message = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    match level {
        0 => log::error!("wireguard-go: {}", message.trim_end()),
        1 => log::warn!("wireguard-go: {}", message.trim_end()),
        2 => log::info!("wireguard-go: {}", message.trim_end()),
        _ => log::debug!("wireguard-go: {}", message.trim_end()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    Controller::new().await?.run().await
}
