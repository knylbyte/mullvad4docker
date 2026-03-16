use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Local};
use mullvad_daita_controller::config::{DEFAULT_MTU, InterfaceMtu, ParsedConfig};
use mullvad_daita_controller::killswitch;
use mullvad_daita_controller::mtu;
use mullvad_daita_controller::uapi::UapiClient;
use reqwest::Client;
use std::env;
use std::fs;
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use talpid_tunnel_config_client::request_ephemeral_peer;
use talpid_types::net::wireguard::PrivateKey;
use tempfile::NamedTempFile;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;

const MULLVAD_CONNECTION_TEST_URL: &str = "https://am.i.mullvad.net/connected";
const MULLVAD_CONNECTION_SUCCESS_TEXT: &str = "You are connected to Mullvad";
const MULLVAD_CONNECTION_TEST_ATTEMPTS: u32 = 6;
const MULLVAD_CONNECTION_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const MULLVAD_CONNECTION_TEST_RETRY_DELAY: Duration = Duration::from_secs(5);
const GOTATUN_BIN: &str = "gotatun";
const GOTATUN_SOCKET_DIR: &str = "/var/run/wireguard";
const GOTATUN_START_TIMEOUT: Duration = Duration::from_secs(10);
const GOTATUN_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const GOTATUN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const GOTATUN_RUST_LOG: &str = "gotatun=info,gotatun::device::uapi=warn";
const POLICY_RULE_PRIORITY: u32 = 10000;
const SUPPRESS_RULE_PRIORITY: u32 = 10001;
const SRC_VALID_MARK_PATH: &str = "/proc/sys/net/ipv4/conf/all/src_valid_mark";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteFamily {
    Ipv4,
    Ipv6,
}

impl RouteFamily {
    fn family_flag(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }
}

#[derive(Debug)]
struct PolicyRoutingState {
    fwmark: u32,
    families: Vec<RouteFamily>,
}

#[derive(Debug, Default)]
struct SystemState {
    endpoint_route: Option<RouteRecord>,
    policy_routing: Option<PolicyRoutingState>,
    killswitch_installed: bool,
    resolv_conf_backup: Option<String>,
}

#[derive(Debug)]
struct UserspaceTunnel {
    child: Child,
    uapi_client: UapiClient,
}

enum ActiveTunnel {
    Userspace(UserspaceTunnel),
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
        if self.runtime.daita_enabled && self.backend == EffectiveBackend::Userspace {
            self.configure_interface_without_dns()?;
            self.activate_daita_userspace().await?;
            self.configure_interface()?;
        } else {
            self.configure_interface()?;
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
        let request = self.config.initial_uapi_request()?;
        self.start_userspace_tunnel_with_request(&request)
    }

    fn start_userspace_tunnel_with_request(&self, request: &str) -> Result<ActiveTunnel> {
        let socket_path = gotatun_socket_path(&self.runtime.interface_name);
        let _ = fs::remove_file(&socket_path);

        let mut child = spawn_gotatun(&self.runtime.interface_name)?;

        let uapi_client = UapiClient::new(socket_path);
        wait_for_userspace_tunnel_ready(
            &mut child,
            &uapi_client,
            &self.runtime.interface_name,
            GOTATUN_START_TIMEOUT,
        )?;

        uapi_client
            .set(request)
            .context("failed to configure gotatun through UAPI")?;

        Ok(ActiveTunnel::Userspace(UserspaceTunnel {
            child,
            uapi_client,
        }))
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
        self.configure_interface_without_dns()?;
        self.apply_dns()?;
        Ok(())
    }

    fn configure_interface_without_dns(&mut self) -> Result<()> {
        self.configure_endpoint_bypass_route()?;
        self.apply_interface_addresses()?;
        self.apply_link_state()?;
        if self.uses_policy_routing() {
            self.install_policy_routing()?;
        } else {
            self.apply_direct_routes()?;
        }
        Ok(())
    }

    async fn activate_daita_userspace(&mut self) -> Result<()> {
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

        let settings = if self.config.is_multihop() {
            let entry_only_settings = self.config.entry_hop_uapi_request()?;
            log::info!("restarting gotatun for multihop DAITA peer exchange");
            self.restart_userspace_tunnel(&entry_only_settings)?;
            self.configure_interface_without_dns()?;

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
            self.config.multihop_daita_uapi_request(
                &ephemeral_private_key,
                entry_response.psk.as_ref(),
                exit_response.psk.as_ref(),
                &daita,
            )?
        } else {
            let daita = exit_response
                .daita
                .ok_or_else(|| anyhow!("relay config service returned no DAITA settings"))?;
            self.config.daita_uapi_request(
                &ephemeral_private_key,
                exit_response.psk.as_ref(),
                &daita,
            )?
        };

        log::info!("restarting gotatun to apply final DAITA configuration");
        self.restart_userspace_tunnel(&settings)
            .context("failed to apply DAITA reconfiguration to gotatun")?;
        Ok(())
    }

    fn restart_userspace_tunnel(&mut self, request: &str) -> Result<()> {
        self.remove_policy_routing()?;
        self.remove_endpoint_bypass_route()?;
        self.stop_tunnel()?;
        self.tunnel = Some(self.start_userspace_tunnel_with_request(request)?);
        Ok(())
    }

    fn shutdown(&mut self, startup_failed: bool) -> Result<()> {
        if !startup_failed && self.post_up_completed {
            self.run_hooks("PreDown", &self.config.hooks.pre_down)?;
        }

        self.restore_dns()?;
        self.remove_policy_routing()?;
        self.remove_endpoint_bypass_route()?;
        self.stop_tunnel()?;
        self.remove_killswitch()?;

        if !startup_failed && self.post_up_completed {
            self.run_hooks("PostDown", &self.config.hooks.post_down)?;
        }

        Ok(())
    }

    fn install_killswitch(&mut self) -> Result<()> {
        log::info!("installing container kill switch");
        killswitch::install(
            &self.runtime.interface_name,
            self.config.entry_peer.endpoint,
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
            Some(ActiveTunnel::Userspace(mut tunnel)) => {
                terminate_child(&mut tunnel.child, GOTATUN_STOP_TIMEOUT)
                    .context("failed to stop gotatun process")?;
                let _ = fs::remove_file(tunnel.uapi_client.socket_path());
            }
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
        if self.system_state.endpoint_route.is_some() {
            return Ok(());
        }

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

    fn apply_direct_routes(&self) -> Result<()> {
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

    fn uses_policy_routing(&self) -> bool {
        !self.full_tunnel_families().is_empty()
    }

    fn full_tunnel_families(&self) -> Vec<RouteFamily> {
        let allowed_ips = self.config.effective_allowed_ips();
        let mut families = Vec::new();

        if allowed_ips
            .iter()
            .any(|network| network.is_ipv4() && network.prefix() == 0)
        {
            families.push(RouteFamily::Ipv4);
        }
        if allowed_ips
            .iter()
            .any(|network| network.is_ipv6() && network.prefix() == 0)
        {
            families.push(RouteFamily::Ipv6);
        }

        families
    }

    fn install_policy_routing(&mut self) -> Result<()> {
        if self.system_state.policy_routing.is_some() {
            return Ok(());
        }

        let fwmark = self.config.effective_fwmark();
        let families = self.full_tunnel_families();
        if families.is_empty() {
            return Ok(());
        }

        log::info!(
            "installing policy routing with fwmark {} for {:?}",
            fwmark,
            families
        );

        if families.contains(&RouteFamily::Ipv4) {
            ensure_src_valid_mark_enabled()?;
        }

        for family in &families {
            let _ = run_ip(build_policy_suppress_rule_del_args(*family));
            let _ = run_ip(build_policy_mark_rule_del_args(*family, fwmark));
            run_ip(build_policy_default_route_args(
                *family,
                self.runtime.interface_name.as_str(),
                fwmark,
            ))?;
            run_ip(build_policy_mark_rule_add_args(*family, fwmark))?;
            run_ip(build_policy_suppress_rule_add_args(*family))?;
        }

        self.system_state.policy_routing = Some(PolicyRoutingState { fwmark, families });
        Ok(())
    }

    fn remove_policy_routing(&mut self) -> Result<()> {
        let Some(state) = self.system_state.policy_routing.take() else {
            return Ok(());
        };

        for family in state.families.iter().copied() {
            let _ = run_ip(build_policy_suppress_rule_del_args(family));
            let _ = run_ip(build_policy_mark_rule_del_args(family, state.fwmark));
            let _ = run_ip(build_policy_default_route_del_args(
                family,
                self.runtime.interface_name.as_str(),
                state.fwmark,
            ));
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

fn gotatun_socket_path(interface_name: &str) -> PathBuf {
    Path::new(GOTATUN_SOCKET_DIR).join(format!("{interface_name}.sock"))
}

fn spawn_gotatun(interface_name: &str) -> Result<Child> {
    let mut child = Command::new(GOTATUN_BIN)
        .args(["--foreground", "--disable-drop-privileges", interface_name])
        .env("CLICOLOR", "0")
        .env("NO_COLOR", "1")
        .env("RUST_LOG", GOTATUN_RUST_LOG)
        .env("RUST_LOG_STYLE", "never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {}", GOTATUN_BIN))?;

    if let Some(stdout) = child.stdout.take() {
        spawn_gotatun_log_pump(stdout);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_gotatun_log_pump(stderr);
    }

    Ok(child)
}

fn spawn_gotatun_log_pump<R>(reader: R)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };
            let Some(line) = format_gotatun_log_line(&line) else {
                continue;
            };
            eprintln!("{line}");
        }
    });
}

fn format_gotatun_log_line(line: &str) -> Option<String> {
    let line = strip_ansi_escapes(line);
    let line = line.trim();
    if line.is_empty()
        || line.starts_with("at ")
        || line.contains("New UAPI connection on unix socket")
        || line.contains("Peer added")
        || line.contains("SIGTERM received")
        || line.contains("GotaTun is shutting down")
    {
        return None;
    }

    let Some((timestamp, rest)) = line.split_once(' ') else {
        return Some(format!("[gotatun] {line}"));
    };
    let Some(normalized_timestamp) = normalize_gotatun_timestamp(timestamp) else {
        return Some(format!("[gotatun] {line}"));
    };
    let rest = rest.trim_start();

    let mut parts = rest.splitn(3, ' ');
    let level = parts.next()?.trim();
    let target = parts.next()?.trim().trim_end_matches(':');
    let message = parts.next()?.trim();

    if level.is_empty() || target.is_empty() || message.is_empty() {
        return Some(format!("[gotatun] {line}"));
    }

    Some(format!(
        "[{normalized_timestamp} {level:<5} {target}] {message}"
    ))
}

fn normalize_gotatun_timestamp(timestamp: &str) -> Option<String> {
    let parsed = DateTime::parse_from_rfc3339(timestamp).ok()?;
    Some(format_log_timestamp(parsed.with_timezone(&Local)))
}

fn format_log_timestamp<Tz>(timestamp: DateTime<Tz>) -> String
where
    Tz: chrono::TimeZone,
    Tz::Offset: std::fmt::Display,
{
    timestamp.format("%Y-%m-%dT%H:%M:%S%:z").to_string()
}

fn init_logger() {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format(|buf, record| {
        writeln!(
            buf,
            "[{} {:<5} {}] {}",
            format_log_timestamp(Local::now()),
            record.level(),
            record.target(),
            record.args()
        )
    });
    logger.init();
}

fn strip_ansi_escapes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            let _ = chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }

        output.push(ch);
    }

    output
}

fn wait_for_userspace_tunnel_ready(
    child: &mut Child,
    uapi_client: &UapiClient,
    interface_name: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;

    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll gotatun child process")?
        {
            bail!("gotatun exited before it became ready: {}", status);
        }

        if interface_exists(interface_name) && uapi_client.get().is_ok() {
            return Ok(());
        }

        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for gotatun interface {} and UAPI socket {}",
                interface_name,
                uapi_client.socket_path().display()
            );
        }

        thread::sleep(GOTATUN_POLL_INTERVAL);
    }
}

fn interface_exists(interface_name: &str) -> bool {
    Path::new("/sys/class/net").join(interface_name).exists()
}

fn terminate_child(child: &mut Child, timeout: Duration) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }

    let pid = child.id() as libc::pid_t;
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("failed to send SIGTERM to gotatun");
        }
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(GOTATUN_POLL_INTERVAL);
    }

    child
        .kill()
        .context("failed to SIGKILL gotatun after graceful shutdown timeout")?;
    let _ = child.wait();
    Ok(())
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

fn build_policy_default_route_args(
    family: RouteFamily,
    interface_name: &str,
    table: u32,
) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "route".into(),
        "replace".into(),
        "default".into(),
        "dev".into(),
        interface_name.into(),
        "table".into(),
        table.to_string(),
    ]
}

fn build_policy_default_route_del_args(
    family: RouteFamily,
    interface_name: &str,
    table: u32,
) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "route".into(),
        "del".into(),
        "default".into(),
        "dev".into(),
        interface_name.into(),
        "table".into(),
        table.to_string(),
    ]
}

fn build_policy_mark_rule_add_args(family: RouteFamily, fwmark: u32) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "rule".into(),
        "add".into(),
        "not".into(),
        "fwmark".into(),
        fwmark.to_string(),
        "table".into(),
        fwmark.to_string(),
        "priority".into(),
        POLICY_RULE_PRIORITY.to_string(),
    ]
}

fn build_policy_mark_rule_del_args(family: RouteFamily, fwmark: u32) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "rule".into(),
        "del".into(),
        "not".into(),
        "fwmark".into(),
        fwmark.to_string(),
        "table".into(),
        fwmark.to_string(),
        "priority".into(),
        POLICY_RULE_PRIORITY.to_string(),
    ]
}

fn build_policy_suppress_rule_add_args(family: RouteFamily) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "rule".into(),
        "add".into(),
        "table".into(),
        "main".into(),
        "suppress_prefixlength".into(),
        "0".into(),
        "priority".into(),
        SUPPRESS_RULE_PRIORITY.to_string(),
    ]
}

fn build_policy_suppress_rule_del_args(family: RouteFamily) -> Vec<String> {
    vec![
        family.family_flag().into(),
        "rule".into(),
        "del".into(),
        "table".into(),
        "main".into(),
        "suppress_prefixlength".into(),
        "0".into(),
        "priority".into(),
        SUPPRESS_RULE_PRIORITY.to_string(),
    ]
}

fn ensure_src_valid_mark_enabled() -> Result<()> {
    let current = fs::read_to_string(SRC_VALID_MARK_PATH)
        .context("failed to read net.ipv4.conf.all.src_valid_mark")?;
    validate_src_valid_mark_value(&current)
}

fn validate_src_valid_mark_value(current: &str) -> Result<()> {
    if current.trim() == "1" {
        return Ok(());
    }

    bail!(
        "full-tunnel policy routing requires net.ipv4.conf.all.src_valid_mark=1; set it via container sysctls"
    );
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

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    Controller::new().await?.run().await
}

#[cfg(test)]
mod tests {
    use super::{
        EffectiveBackend, GOTATUN_SOCKET_DIR, POLICY_RULE_PRIORITY, RequestedBackend, RouteFamily,
        SUPPRESS_RULE_PRIORITY, build_policy_default_route_args,
        build_policy_default_route_del_args, build_policy_mark_rule_add_args,
        build_policy_mark_rule_del_args, build_policy_suppress_rule_add_args,
        build_policy_suppress_rule_del_args, format_gotatun_log_line, format_log_timestamp,
        gotatun_socket_path, interface_exists, is_mullvad_connection_confirmed,
        normalize_gotatun_timestamp, normalize_response_body, resolve_backend, strip_ansi_escapes,
        validate_src_valid_mark_value,
    };
    use anyhow::{Result, anyhow};
    use chrono::{DateTime, Local};

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
    fn builds_gotatun_socket_path() {
        assert_eq!(
            gotatun_socket_path("wg100").to_string_lossy(),
            format!("{}/wg100.sock", GOTATUN_SOCKET_DIR)
        );
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

    #[test]
    fn interface_exists_returns_false_for_unknown_interface() {
        assert!(!interface_exists("mullvad4docker-does-not-exist"));
    }

    #[test]
    fn strips_ansi_escape_sequences_from_gotatun_logs() {
        assert_eq!(
            strip_ansi_escapes("\u{1b}[32mINFO\u{1b}[0m gotatun::unix"),
            "INFO gotatun::unix"
        );
    }

    #[test]
    fn normalizes_gotatun_timestamps() {
        let expected = format_log_timestamp(
            DateTime::parse_from_rfc3339("2026-03-16T18:06:41.586272Z")
                .unwrap()
                .with_timezone(&Local),
        );
        assert_eq!(
            normalize_gotatun_timestamp("2026-03-16T18:06:41.586272Z"),
            Some(expected.clone())
        );
        assert_eq!(
            normalize_gotatun_timestamp("2026-03-16T18:06:41Z"),
            Some(expected)
        );
        assert_eq!(normalize_gotatun_timestamp("not-a-timestamp"), None);
    }

    #[test]
    fn formats_gotatun_log_lines_like_controller_logs() {
        let started_at = format_log_timestamp(
            DateTime::parse_from_rfc3339("2026-03-16T18:06:41.586272Z")
                .unwrap()
                .with_timezone(&Local),
        );
        assert_eq!(
            format_gotatun_log_line(
                "  2026-03-16T18:06:41.586272Z  INFO gotatun::unix: GotaTun started successfully  "
            ),
            Some(format!(
                "[{started_at} INFO  gotatun::unix] GotaTun started successfully"
            ))
        );
        let daita_at = format_log_timestamp(
            DateTime::parse_from_rfc3339("2026-03-16T18:06:42.105748Z")
                .unwrap()
                .with_timezone(&Local),
        );
        assert_eq!(
            format_gotatun_log_line(
                "2026-03-16T18:06:42.105748Z  INFO gotatun::device::daita::hooks: Initializing DAITA"
            ),
            Some(format!(
                "[{daita_at} INFO  gotatun::device::daita::hooks] Initializing DAITA"
            ))
        );
    }

    #[test]
    fn filters_and_falls_back_for_gotatun_log_lines() {
        assert_eq!(
            format_gotatun_log_line("    at gotatun/src/main.rs:1"),
            None
        );
        assert_eq!(format_gotatun_log_line(""), None);
        assert_eq!(
            format_gotatun_log_line("thread 'tokio-rt-worker' panicked"),
            Some("[gotatun] thread 'tokio-rt-worker' panicked".to_string())
        );
    }

    #[test]
    fn builds_policy_routing_commands() {
        assert_eq!(
            build_policy_default_route_args(RouteFamily::Ipv4, "wg0", 51820),
            vec![
                "-4", "route", "replace", "default", "dev", "wg0", "table", "51820"
            ]
        );
        assert_eq!(
            build_policy_default_route_del_args(RouteFamily::Ipv6, "wg0", 51820),
            vec![
                "-6", "route", "del", "default", "dev", "wg0", "table", "51820"
            ]
        );
        assert_eq!(
            build_policy_mark_rule_add_args(RouteFamily::Ipv4, 51820),
            vec![
                "-4",
                "rule",
                "add",
                "not",
                "fwmark",
                "51820",
                "table",
                "51820",
                "priority",
                &POLICY_RULE_PRIORITY.to_string()
            ]
        );
        assert_eq!(
            build_policy_mark_rule_del_args(RouteFamily::Ipv6, 51820),
            vec![
                "-6",
                "rule",
                "del",
                "not",
                "fwmark",
                "51820",
                "table",
                "51820",
                "priority",
                &POLICY_RULE_PRIORITY.to_string()
            ]
        );
        assert_eq!(
            build_policy_suppress_rule_add_args(RouteFamily::Ipv4),
            vec![
                "-4",
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "priority",
                &SUPPRESS_RULE_PRIORITY.to_string()
            ]
        );
        assert_eq!(
            build_policy_suppress_rule_del_args(RouteFamily::Ipv6),
            vec![
                "-6",
                "rule",
                "del",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "priority",
                &SUPPRESS_RULE_PRIORITY.to_string()
            ]
        );
    }

    #[test]
    fn validates_src_valid_mark_requirement() {
        assert!(validate_src_valid_mark_value("1\n").is_ok());
        let error = validate_src_valid_mark_value("0\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("src_valid_mark=1"));
        assert!(error.contains("container sysctls"));
    }
}
