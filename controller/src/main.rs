use anyhow::{Context, Result, anyhow, bail};
use mullvad_daita_controller::config::{DEFAULT_MTU, InterfaceMtu, ParsedConfig};
use mullvad_daita_controller::killswitch;
use mullvad_daita_controller::mtu;
use reqwest::Client;
use std::env;
use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::net::IpAddr;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::Duration;
use talpid_tunnel_config_client::request_ephemeral_peer;
use talpid_types::net::wireguard::PrivateKey;
use tempfile::NamedTempFile;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;
use tun::AbstractDevice;
use wireguard_go_rs::{LoggingContext, Tunnel, WgLogLevel};

const DAITA_EVENTS_CAPACITY: u32 = 2048;
const DAITA_ACTIONS_CAPACITY: u32 = 1024;
const MULLVAD_CONNECTION_TEST_URL: &str = "https://am.i.mullvad.net/connected";
const MULLVAD_CONNECTION_SUCCESS_TEXT: &str = "You are connected to Mullvad";
const MULLVAD_CONNECTION_TEST_ATTEMPTS: u32 = 6;
const MULLVAD_CONNECTION_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const MULLVAD_CONNECTION_TEST_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedBackend {
    Auto,
    Userspace,
    Kernel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectiveBackend {
    Userspace,
    Kernel,
}

impl RequestedBackend {
    fn from_env_value(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "userspace" => Ok(Self::Userspace),
            "kernel" => Ok(Self::Kernel),
            _ => bail!("WG_BACKEND must be auto, userspace, or kernel"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
        }
    }
}

impl EffectiveBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
        }
    }
}

#[derive(Clone, Debug)]
struct RuntimeConfig {
    daita_enabled: bool,
    killswitch_enabled: bool,
    interface_name: String,
    config_file: PathBuf,
    requested_backend: RequestedBackend,
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

enum ActiveTunnel {
    Userspace(Tunnel),
    Kernel,
}

struct Controller {
    runtime: RuntimeConfig,
    backend: EffectiveBackend,
    config: ParsedConfig,
    tunnel: Option<ActiveTunnel>,
    system_state: SystemState,
    post_up_completed: bool,
    effective_mtu: u16,
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
            requested_backend: RequestedBackend::from_env_value(
                &env::var("WG_BACKEND").unwrap_or_else(|_| "auto".to_string()),
            )?,
        })
    }
}

impl Controller {
    async fn new() -> Result<Self> {
        let runtime = RuntimeConfig::from_env()?;
        let config = ParsedConfig::from_file(&runtime.config_file)?;
        let backend = resolve_backend(runtime.requested_backend, runtime.daita_enabled, || {
            probe_kernel_backend()
        })?;

        Ok(Self {
            runtime,
            backend,
            config,
            tunnel: None,
            system_state: SystemState::default(),
            post_up_completed: false,
            effective_mtu: DEFAULT_MTU,
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
            "starting tunnel controller with interface {}, config {}, requested backend {}, effective backend {}",
            self.runtime.interface_name,
            self.runtime.config_file.display(),
            self.runtime.requested_backend.as_str(),
            self.backend.as_str()
        );

        self.effective_mtu = self.resolve_interface_mtu().await?;
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
        self.verify_mullvad_connection().await?;
        self.post_up_completed = true;

        if self.runtime.daita_enabled {
            log::info!(
                "{} tunnel started and DAITA activation completed",
                self.backend.as_str()
            );
        } else {
            log::info!(
                "{} tunnel started without DAITA activation",
                self.backend.as_str()
            );
        }

        Ok(())
    }

    fn start_tunnel(&mut self) -> Result<()> {
        let tunnel = match self.backend {
            EffectiveBackend::Userspace => self.start_userspace_tunnel()?,
            EffectiveBackend::Kernel => self.start_kernel_tunnel()?,
        };
        self.tunnel = Some(tunnel);
        Ok(())
    }

    fn start_userspace_tunnel(&self) -> Result<ActiveTunnel> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(&self.runtime.interface_name);
        tun_config.mtu(self.effective_mtu);
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
            self.effective_mtu as isize,
            &settings,
            owned_fd,
            Some(wireguard_log_callback),
            0 as LoggingContext,
        )
        .map_err(|error| anyhow!("failed to start wireguard-go tunnel: {error}"))?;

        Ok(ActiveTunnel::Userspace(tunnel))
    }

    fn start_kernel_tunnel(&self) -> Result<ActiveTunnel> {
        run_ip([
            "link",
            "add",
            "dev",
            self.runtime.interface_name.as_str(),
            "type",
            "wireguard",
        ])?;

        let config_file = self.write_kernel_config_file()?;
        let apply_result = run_wg([
            "setconf",
            self.runtime.interface_name.as_str(),
            config_file.path().to_string_lossy().as_ref(),
        ]);

        if let Err(error) = apply_result {
            let _ = run_ip([
                "link",
                "delete",
                "dev",
                self.runtime.interface_name.as_str(),
            ]);
            return Err(error);
        }

        Ok(ActiveTunnel::Kernel)
    }

    fn write_kernel_config_file(&self) -> Result<NamedTempFile> {
        let mut file =
            NamedTempFile::new().context("failed to create temporary kernel WireGuard config")?;
        use std::io::Write;
        file.write_all(self.config.kernel_settings().as_bytes())
            .context("failed to write temporary kernel WireGuard config")?;
        Ok(file)
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
        let tunnel = self.active_userspace_tunnel()?;
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
            tunnel.set_config(&entry_only_settings).map_err(|error| {
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

        tunnel
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

        tunnel
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

    fn active_userspace_tunnel(&self) -> Result<&Tunnel> {
        match self.tunnel.as_ref() {
            Some(ActiveTunnel::Userspace(tunnel)) => Ok(tunnel),
            Some(ActiveTunnel::Kernel) => {
                bail!("DAITA is only supported with the userspace backend")
            }
            None => bail!("tunnel is not active"),
        }
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
        match self.tunnel.take() {
            Some(ActiveTunnel::Userspace(tunnel)) => tunnel
                .turn_off()
                .map_err(|error| anyhow!("failed to stop wireguard-go tunnel: {error}"))?,
            Some(ActiveTunnel::Kernel) => {
                run_ip([
                    "link",
                    "delete",
                    "dev",
                    self.runtime.interface_name.as_str(),
                ])?;
            }
            None => {}
        }
        Ok(())
    }

    async fn verify_mullvad_connection(&self) -> Result<()> {
        let client = Client::builder()
            .timeout(MULLVAD_CONNECTION_TEST_TIMEOUT)
            .user_agent(concat!("mullvad4docker/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to create HTTP client for Mullvad connection test")?;

        let mut last_error = None;
        for attempt in 1..=MULLVAD_CONNECTION_TEST_ATTEMPTS {
            match self.try_mullvad_connection_check(&client).await {
                Ok(()) => {
                    log::info!("Mullvad connection test passed");
                    return Ok(());
                }
                Err(error) => {
                    log::warn!(
                        "Mullvad connection test attempt {}/{} failed: {}",
                        attempt,
                        MULLVAD_CONNECTION_TEST_ATTEMPTS,
                        error
                    );
                    last_error = Some(error);
                    if attempt < MULLVAD_CONNECTION_TEST_ATTEMPTS {
                        sleep(MULLVAD_CONNECTION_TEST_RETRY_DELAY).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Mullvad connection test failed")))
    }

    async fn try_mullvad_connection_check(&self, client: &Client) -> Result<()> {
        let response = client
            .get(MULLVAD_CONNECTION_TEST_URL)
            .send()
            .await
            .context("failed to request Mullvad connection test page")?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("failed to read Mullvad connection test response body")?;
        let body = String::from_utf8_lossy(&body);
        let normalized_body = normalize_response_body(&body);

        log::info!("Mullvad connection test response: {}", normalized_body);

        if !status.is_success() {
            bail!(
                "Mullvad connection test returned HTTP {} with body: {}",
                status,
                normalized_body
            );
        }
        if !is_mullvad_connection_confirmed(&body) {
            bail!(
                "unexpected Mullvad connection test response: {}",
                normalized_body
            );
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
            &self.effective_mtu.to_string(),
            "up",
        ])
    }

    async fn resolve_interface_mtu(&self) -> Result<u16> {
        match self.config.mtu {
            InterfaceMtu::Fixed(mtu) => Ok(mtu),
            InterfaceMtu::Auto => {
                let endpoint = self.config.entry_peer.endpoint;
                log::info!(
                    "probing auto MTU for {} with {} workers",
                    endpoint,
                    mtu::AUTO_MTU_WORKERS
                );
                let result =
                    tokio::task::spawn_blocking(move || mtu::detect_wireguard_mtu(endpoint))
                        .await
                        .map_err(|error| anyhow!("auto MTU probe task failed: {error}"))??;

                log::info!(
                    "auto MTU detected for {}: outer path MTU {}, WireGuard overhead {}, using interface MTU {}",
                    endpoint,
                    result.outer_path_mtu,
                    result.wireguard_overhead,
                    result.wireguard_mtu
                );

                Ok(result.wireguard_mtu)
            }
        }
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

fn resolve_backend<F>(
    requested: RequestedBackend,
    daita_enabled: bool,
    kernel_probe: F,
) -> Result<EffectiveBackend>
where
    F: FnOnce() -> Result<()>,
{
    if !cfg!(target_os = "linux") {
        return match requested {
            RequestedBackend::Kernel => bail!("kernel backend is only supported on Linux"),
            RequestedBackend::Auto | RequestedBackend::Userspace => Ok(EffectiveBackend::Userspace),
        };
    }

    match requested {
        RequestedBackend::Userspace => Ok(EffectiveBackend::Userspace),
        RequestedBackend::Kernel => {
            if daita_enabled {
                bail!("DAITA requires the userspace backend; WG_BACKEND=kernel is unsupported");
            }
            kernel_probe()?;
            Ok(EffectiveBackend::Kernel)
        }
        RequestedBackend::Auto => {
            if daita_enabled {
                log::info!("DAITA is enabled; forcing userspace backend");
                return Ok(EffectiveBackend::Userspace);
            }

            match kernel_probe() {
                Ok(()) => Ok(EffectiveBackend::Kernel),
                Err(error) => {
                    log::warn!(
                        "kernel backend probe failed; falling back to userspace backend: {}",
                        error
                    );
                    Ok(EffectiveBackend::Userspace)
                }
            }
        }
    }
}

fn probe_kernel_backend() -> Result<()> {
    let temp_interface = format!("wgp{}", process::id());
    run_ip([
        "link",
        "add",
        "dev",
        temp_interface.as_str(),
        "type",
        "wireguard",
    ])?;
    run_ip(["link", "delete", "dev", temp_interface.as_str()])?;
    Ok(())
}

fn read_default_route(family_flag: &str) -> Result<DefaultRoute> {
    let output = Command::new("ip")
        .arg(family_flag)
        .args(["route", "show", "default"])
        .output()
        .context("failed to query default route")?;
    if !output.status.success() {
        bail!(
            "ip {} route show default failed with status {}: {}",
            family_flag,
            output.status,
            command_error_text(&output.stdout, &output.stderr)
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

fn run_ip<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    run_command("ip", args)
}

fn run_wg<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    run_command("wg", args)
}

fn run_command<I, S>(program: &str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect::<Vec<_>>();
    let output = Command::new(program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute {} {}", program, args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "{} {} failed with status {}: {}",
            program,
            args.join(" "),
            output.status,
            command_error_text(&output.stdout, &output.stderr)
        );
    }
    Ok(())
}

fn command_error_text(stdout: &[u8], stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }

    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    if !stdout.is_empty() {
        return stdout;
    }

    "no output".to_string()
}

fn is_mullvad_connection_confirmed(body: &str) -> bool {
    body.contains(MULLVAD_CONNECTION_SUCCESS_TEXT)
}

fn normalize_response_body(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
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

#[cfg(test)]
mod tests {
    use super::{
        EffectiveBackend, RequestedBackend, is_mullvad_connection_confirmed,
        normalize_response_body, resolve_backend,
    };
    use anyhow::{Result, anyhow};

    #[test]
    fn parses_backend_modes() {
        assert_eq!(
            RequestedBackend::from_env_value("auto").unwrap(),
            RequestedBackend::Auto
        );
        assert_eq!(
            RequestedBackend::from_env_value("userspace").unwrap(),
            RequestedBackend::Userspace
        );
        assert_eq!(
            RequestedBackend::from_env_value("kernel").unwrap(),
            RequestedBackend::Kernel
        );
    }

    #[test]
    fn rejects_invalid_backend_mode() {
        let error = RequestedBackend::from_env_value("invalid").unwrap_err();
        assert!(error.to_string().contains("WG_BACKEND"));
    }

    #[test]
    fn rejects_kernel_backend_when_daita_is_enabled() {
        let error = resolve_backend(RequestedBackend::Kernel, true, || Ok(())).unwrap_err();
        let error = error.to_string();
        if cfg!(target_os = "linux") {
            assert!(error.contains("DAITA requires the userspace backend"));
        } else {
            assert!(error.contains("only supported on Linux"));
        }
    }

    #[test]
    fn auto_backend_forces_userspace_when_daita_is_enabled() {
        let backend = resolve_backend(RequestedBackend::Auto, true, || -> Result<()> {
            Err(anyhow!("probe should not run"))
        })
        .unwrap();
        assert_eq!(backend, EffectiveBackend::Userspace);
    }

    #[test]
    fn auto_backend_uses_kernel_when_probe_succeeds() {
        let backend = resolve_backend(RequestedBackend::Auto, false, || Ok(())).unwrap();
        let expected = if cfg!(target_os = "linux") {
            EffectiveBackend::Kernel
        } else {
            EffectiveBackend::Userspace
        };
        assert_eq!(backend, expected);
    }

    #[test]
    fn auto_backend_falls_back_to_userspace_when_probe_fails() {
        let backend = resolve_backend(RequestedBackend::Auto, false, || -> Result<()> {
            Err(anyhow!("kernel unavailable"))
        })
        .unwrap();
        assert_eq!(backend, EffectiveBackend::Userspace);
    }

    #[test]
    fn accepts_connected_response() {
        assert!(is_mullvad_connection_confirmed(
            "You are connected to Mullvad. Your IP address is 1.2.3.4\n"
        ));
    }

    #[test]
    fn rejects_disconnected_response() {
        assert!(!is_mullvad_connection_confirmed(
            "You are not connected to Mullvad. Your IP address is 1.2.3.4\n"
        ));
    }

    #[test]
    fn normalizes_whitespace_for_logging() {
        assert_eq!(
            normalize_response_body("You are connected\n  to Mullvad.\t"),
            "You are connected to Mullvad."
        );
    }
}
