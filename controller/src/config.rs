use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use ipnetwork::IpNetwork;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use talpid_tunnel_config_client::DaitaSettings;
use talpid_types::net::wireguard::{PresharedKey, PrivateKey, PublicKey};

pub const DEFAULT_MTU: u16 = 1380;
const DEFAULT_CONFIG_SERVICE_IPV4: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);
const DAITA_MAX_DELAYED_PACKETS: usize = 1024;
const DAITA_MIN_DELAY_CAPACITY: usize = 50;

#[derive(Clone, Debug, Default)]
pub struct Hooks {
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeerSettings {
    pub public_key: PublicKey,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
    pub preshared_key: Option<PresharedKey>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Copy, Debug)]
pub enum InterfaceMtu {
    Fixed(u16),
    Auto,
}

#[derive(Clone, Debug)]
pub struct ParsedConfig {
    pub private_key: PrivateKey,
    pub addresses: Vec<IpNetwork>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: InterfaceMtu,
    pub fwmark: Option<u32>,
    pub hooks: Hooks,
    pub entry_peer: PeerSettings,
    pub exit_peer: Option<PeerSettings>,
}

impl ParsedConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read WireGuard config {}", path.display()))?;

        let mut section = String::new();
        let mut interface_private_key = None;
        let mut interface_addresses = Vec::new();
        let mut interface_dns = Vec::new();
        let mut interface_mtu = None;
        let mut interface_fwmark = None;
        let mut hooks = Hooks::default();

        let mut parsed_peers = Vec::new();
        let mut current_peer = PendingPeer::default();
        let mut in_peer_section = false;

        for (index, raw_line) in content.lines().enumerate() {
            let line_number = index + 1;
            let line = strip_comments(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                if in_peer_section {
                    parsed_peers.push(current_peer.finish()?);
                    current_peer = PendingPeer::default();
                    in_peer_section = false;
                }

                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                if section == "peer" {
                    in_peer_section = true;
                }
                continue;
            }

            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid line {} in WireGuard config", line_number))?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            match section.as_str() {
                "interface" => match key.as_str() {
                    "privatekey" => {
                        interface_private_key = Some(
                            PrivateKey::from_base64(value)
                                .context("invalid Interface.PrivateKey")?,
                        );
                    }
                    "address" => {
                        interface_addresses.extend(parse_interface_networks(value).with_context(
                            || format!("invalid Interface.Address on line {}", line_number),
                        )?);
                    }
                    "dns" => {
                        interface_dns.extend(parse_ip_list(value).with_context(|| {
                            format!("invalid Interface.DNS on line {}", line_number)
                        })?);
                    }
                    "mtu" => {
                        if value.eq_ignore_ascii_case("auto") {
                            interface_mtu = Some(InterfaceMtu::Auto);
                        } else {
                            interface_mtu =
                                Some(InterfaceMtu::Fixed(value.parse::<u16>().with_context(
                                    || format!("invalid Interface.MTU on line {}", line_number),
                                )?));
                        }
                    }
                    "fwmark" => {
                        interface_fwmark = Some(value.parse::<u32>().with_context(|| {
                            format!("invalid Interface.FwMark on line {}", line_number)
                        })?);
                    }
                    "preup" => hooks.pre_up.push(value.to_string()),
                    "postup" => hooks.post_up.push(value.to_string()),
                    "predown" => hooks.pre_down.push(value.to_string()),
                    "postdown" => hooks.post_down.push(value.to_string()),
                    "table" | "saveconfig" | "listenport" => {
                        log::warn!(
                            "ignoring unsupported Interface.{} in {}",
                            key,
                            path.display()
                        );
                    }
                    _ => {
                        log::warn!("ignoring unknown Interface.{} in {}", key, path.display());
                    }
                },
                "peer" => match key.as_str() {
                    "publickey" => {
                        current_peer.public_key =
                            Some(PublicKey::from_base64(value).context("invalid Peer.PublicKey")?);
                    }
                    "endpoint" => {
                        current_peer.endpoint =
                            Some(value.parse::<SocketAddr>().with_context(|| {
                                format!("invalid Peer.Endpoint on line {}", line_number)
                            })?);
                    }
                    "allowedips" => {
                        current_peer
                            .allowed_ips
                            .extend(parse_network_list(value).with_context(|| {
                                format!("invalid Peer.AllowedIPs on line {}", line_number)
                            })?);
                    }
                    "presharedkey" => {
                        current_peer.preshared_key =
                            Some(parse_preshared_key(value).with_context(|| {
                                format!("invalid Peer.PresharedKey on line {}", line_number)
                            })?);
                    }
                    "persistentkeepalive" => {
                        current_peer.persistent_keepalive =
                            Some(value.parse::<u16>().with_context(|| {
                                format!("invalid Peer.PersistentKeepalive on line {}", line_number)
                            })?);
                    }
                    _ => {
                        log::warn!("ignoring unknown Peer.{} in {}", key, path.display());
                    }
                },
                _ => {
                    bail!("unsupported or missing section near line {}", line_number);
                }
            }
        }

        if in_peer_section {
            parsed_peers.push(current_peer.finish()?);
        }

        let private_key =
            interface_private_key.ok_or_else(|| anyhow!("missing Interface.PrivateKey"))?;
        if interface_addresses.is_empty() {
            bail!("missing Interface.Address");
        }

        let (entry_peer, exit_peer) = classify_peers(parsed_peers)?;

        Ok(Self {
            private_key,
            addresses: interface_addresses,
            dns_servers: interface_dns,
            mtu: interface_mtu.unwrap_or(InterfaceMtu::Fixed(DEFAULT_MTU)),
            fwmark: interface_fwmark,
            hooks,
            entry_peer,
            exit_peer,
        })
    }

    pub fn config_service_ipv4(&self) -> Ipv4Addr {
        self.dns_servers
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V4(ipv4) => Some(*ipv4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or(DEFAULT_CONFIG_SERVICE_IPV4)
    }

    pub fn supports_ipv6(&self) -> bool {
        self.addresses.iter().any(IpNetwork::is_ipv6)
    }

    pub fn is_multihop(&self) -> bool {
        self.exit_peer.is_some()
    }

    pub fn exit_peer(&self) -> &PeerSettings {
        self.exit_peer.as_ref().unwrap_or(&self.entry_peer)
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerSettings> {
        self.exit_peer
            .as_ref()
            .into_iter()
            .chain(std::iter::once(&self.entry_peer))
    }

    pub fn effective_allowed_ips(&self) -> Vec<IpNetwork> {
        let enable_ipv6 = self.supports_ipv6();
        self.peers()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .filter(|network| network.is_ipv4() || enable_ipv6)
            .collect()
    }

    pub fn initial_uapi_request(&self) -> Result<String> {
        build_userspace_config(
            &self.private_key,
            self.fwmark,
            self.peers().map(|peer| UserSpacePeerConfig {
                peer: peer.clone(),
                daita: None,
            }),
        )
    }

    pub fn kernel_settings(&self) -> String {
        build_kernel_config(&self.private_key, self.fwmark, self.peers().cloned())
    }

    pub fn daita_uapi_request(
        &self,
        private_key: &PrivateKey,
        preshared_key: Option<&PresharedKey>,
        daita: &DaitaSettings,
    ) -> Result<String> {
        build_userspace_config(
            private_key,
            self.fwmark,
            self.peers().map(|peer| {
                if peer.public_key == self.entry_peer.public_key {
                    let mut peer = peer.clone();
                    peer.preshared_key = preshared_key.cloned();
                    UserSpacePeerConfig {
                        peer,
                        daita: Some(daita),
                    }
                } else {
                    let mut peer = peer.clone();
                    peer.preshared_key = preshared_key
                        .filter(|_| self.exit_peer.is_none())
                        .cloned()
                        .or_else(|| peer.preshared_key.clone());
                    UserSpacePeerConfig { peer, daita: None }
                }
            }),
        )
    }

    pub fn multihop_daita_uapi_request(
        &self,
        private_key: &PrivateKey,
        entry_preshared_key: Option<&PresharedKey>,
        exit_preshared_key: Option<&PresharedKey>,
        daita: &DaitaSettings,
    ) -> Result<String> {
        build_userspace_config(
            private_key,
            self.fwmark,
            self.peers().map(|peer| {
                let mut peer = peer.clone();
                if peer.public_key == self.entry_peer.public_key {
                    peer.preshared_key = entry_preshared_key.cloned();
                    UserSpacePeerConfig {
                        peer,
                        daita: Some(daita),
                    }
                } else if peer.public_key == self.exit_peer().public_key {
                    peer.preshared_key = exit_preshared_key.cloned();
                    UserSpacePeerConfig { peer, daita: None }
                } else {
                    UserSpacePeerConfig { peer, daita: None }
                }
            }),
        )
    }

    pub fn entry_hop_uapi_request(&self) -> Result<String> {
        let mut entry_peer = self.entry_peer.clone();
        let gateway = IpNetwork::from(IpAddr::V4(self.config_service_ipv4()));
        if !entry_peer.allowed_ips.contains(&gateway) {
            entry_peer.allowed_ips.push(gateway);
        }

        build_userspace_config(
            &self.private_key,
            self.fwmark,
            std::iter::once(UserSpacePeerConfig {
                peer: entry_peer,
                daita: None,
            }),
        )
    }
}

#[derive(Clone)]
struct UserSpacePeerConfig<'a> {
    peer: PeerSettings,
    daita: Option<&'a DaitaSettings>,
}

fn build_userspace_config<'a, I>(
    private_key: &PrivateKey,
    fwmark: Option<u32>,
    peers: I,
) -> Result<String>
where
    I: IntoIterator<Item = UserSpacePeerConfig<'a>>,
{
    let mut lines = Vec::new();
    lines.push("set=1".to_string());
    lines.push(conf_line(
        "private_key",
        &hex::encode(private_key.to_bytes()),
    ));
    lines.push(conf_line("listen_port", "0"));
    if let Some(fwmark) = fwmark {
        lines.push(conf_line("fwmark", &fwmark.to_string()));
    }
    lines.push(conf_line("replace_peers", "true"));

    let mut peer_count = 0usize;
    for peer_config in peers {
        let peer = peer_config.peer;
        let allowed_ips = peer.allowed_ips;
        if allowed_ips.is_empty() {
            bail!("peer {} has no allowed IPs", peer.public_key.to_base64());
        }

        peer_count += 1;
        lines.push(conf_line(
            "public_key",
            &hex::encode(peer.public_key.as_bytes()),
        ));
        lines.push(conf_line("endpoint", &peer.endpoint.to_string()));
        lines.push(conf_line("replace_allowed_ips", "true"));
        if let Some(preshared_key) = peer.preshared_key.as_ref() {
            lines.push(conf_line(
                "preshared_key",
                &hex::encode(preshared_key.as_bytes()),
            ));
        }
        if let Some(persistent_keepalive) = peer.persistent_keepalive {
            lines.push(conf_line(
                "persistent_keepalive_interval",
                &persistent_keepalive.to_string(),
            ));
        }
        for allowed_ip in &allowed_ips {
            lines.push(conf_line("allowed_ip", &allowed_ip.to_string()));
        }
        if let Some(daita) = peer_config.daita {
            lines.push(conf_line("daita_enable", "1"));
            for machine in &daita.client_machines {
                lines.push(conf_line("daita_machine", &machine.serialize()));
            }
            lines.push(conf_line(
                "daita_max_delayed_packets",
                &DAITA_MAX_DELAYED_PACKETS.to_string(),
            ));
            lines.push(conf_line(
                "daita_min_delay_capacity",
                &DAITA_MIN_DELAY_CAPACITY.to_string(),
            ));
            lines.push(conf_line(
                "daita_max_decoy_frac",
                &daita.max_decoy_frac.to_string(),
            ));
            lines.push(conf_line(
                "daita_max_delay_frac",
                &daita.max_delay_frac.to_string(),
            ));
        }
    }

    if peer_count == 0 {
        bail!("WireGuard config must contain at least one peer");
    }

    lines.push(String::new());

    Ok(lines.join("\n"))
}

fn build_kernel_config<I>(private_key: &PrivateKey, fwmark: Option<u32>, peers: I) -> String
where
    I: IntoIterator<Item = PeerSettings>,
{
    let mut lines = Vec::new();
    lines.push("[Interface]".to_string());
    lines.push(format!("PrivateKey = {}", private_key.to_base64()));
    if let Some(fwmark) = fwmark {
        lines.push(format!("FwMark = {}", fwmark));
    }
    lines.push(String::new());

    for peer in peers {
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", peer.public_key.to_base64()));
        lines.push(format!("Endpoint = {}", peer.endpoint));
        if let Some(preshared_key) = peer.preshared_key.as_ref() {
            lines.push(format!(
                "PresharedKey = {}",
                base64::engine::general_purpose::STANDARD.encode(preshared_key.as_bytes())
            ));
        }
        if let Some(persistent_keepalive) = peer.persistent_keepalive {
            lines.push(format!("PersistentKeepalive = {}", persistent_keepalive));
        }
        lines.push(format!(
            "AllowedIPs = {}",
            peer.allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        lines.push(String::new());
    }

    lines.join("\n")
}

#[derive(Default)]
struct PendingPeer {
    public_key: Option<PublicKey>,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<IpNetwork>,
    preshared_key: Option<PresharedKey>,
    persistent_keepalive: Option<u16>,
}

impl PendingPeer {
    fn finish(self) -> Result<PeerSettings> {
        Ok(PeerSettings {
            public_key: self
                .public_key
                .ok_or_else(|| anyhow!("missing Peer.PublicKey"))?,
            endpoint: self
                .endpoint
                .ok_or_else(|| anyhow!("missing Peer.Endpoint"))?,
            allowed_ips: if self.allowed_ips.is_empty() {
                bail!("missing Peer.AllowedIPs");
            } else {
                self.allowed_ips
            },
            preshared_key: self.preshared_key,
            persistent_keepalive: self.persistent_keepalive,
        })
    }
}

fn classify_peers(peers: Vec<PeerSettings>) -> Result<(PeerSettings, Option<PeerSettings>)> {
    match peers.len() {
        0 => bail!("WireGuard config must contain at least one [Peer] section"),
        1 => Ok((peers.into_iter().next().unwrap(), None)),
        2 => {
            let mut iter = peers.into_iter();
            let first = iter.next().unwrap();
            let second = iter.next().unwrap();

            let first_is_exit = peer_looks_like_exit(&first);
            let second_is_exit = peer_looks_like_exit(&second);

            let (entry_peer, exit_peer) = match (first_is_exit, second_is_exit) {
                (true, false) => (second, first),
                (false, true) => (first, second),
                _ => {
                    bail!("multihop config must contain exactly one exit peer with a default route")
                }
            };

            let exit_endpoint_route = IpNetwork::from(exit_peer.endpoint.ip());
            if !entry_peer.allowed_ips.contains(&exit_endpoint_route) {
                bail!(
                    "multihop config entry peer must route the exit endpoint {}",
                    exit_peer.endpoint.ip()
                );
            }

            Ok((entry_peer, Some(exit_peer)))
        }
        _ => bail!("configs with more than two peers are not supported"),
    }
}

fn peer_looks_like_exit(peer: &PeerSettings) -> bool {
    peer.allowed_ips.iter().any(|network| network.prefix() == 0)
}

#[cfg(test)]
mod tests {
    use super::{InterfaceMtu, ParsedConfig, PeerSettings, classify_peers};
    use ipnetwork::IpNetwork;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use talpid_tunnel_config_client::DaitaSettings;
    use talpid_types::net::wireguard::PrivateKey;
    use talpid_types::net::wireguard::PublicKey;

    fn peer(endpoint: Ipv4Addr, allowed_ips: &[IpNetwork]) -> PeerSettings {
        PeerSettings {
            public_key: PublicKey::from([endpoint.octets()[3]; 32]),
            endpoint: SocketAddr::new(IpAddr::V4(endpoint), 51820),
            allowed_ips: allowed_ips.to_vec(),
            preshared_key: None,
            persistent_keepalive: None,
        }
    }

    #[test]
    fn classifies_single_hop_peer() {
        let input = vec![peer(
            Ipv4Addr::new(185, 65, 135, 1),
            &[IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
        )];

        let (entry_peer, exit_peer) = classify_peers(input).unwrap();

        assert_eq!(
            entry_peer.endpoint.ip(),
            IpAddr::V4(Ipv4Addr::new(185, 65, 135, 1))
        );
        assert!(exit_peer.is_none());
    }

    #[test]
    fn classifies_multihop_peers_by_default_route_and_exit_endpoint() {
        let exit_endpoint = Ipv4Addr::new(185, 65, 135, 10);
        let entry_endpoint = Ipv4Addr::new(146, 70, 1, 20);

        let input = vec![
            peer(
                entry_endpoint,
                &[IpNetwork::new(IpAddr::V4(exit_endpoint), 32).unwrap()],
            ),
            peer(
                exit_endpoint,
                &[IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
            ),
        ];

        let (entry_peer, exit_peer) = classify_peers(input).unwrap();
        let exit_peer = exit_peer.unwrap();

        assert_eq!(entry_peer.endpoint.ip(), IpAddr::V4(entry_endpoint));
        assert_eq!(exit_peer.endpoint.ip(), IpAddr::V4(exit_endpoint));
    }

    #[test]
    fn rejects_invalid_multihop_shape() {
        let input = vec![
            peer(
                Ipv4Addr::new(185, 65, 135, 10),
                &[IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
            ),
            peer(
                Ipv4Addr::new(146, 70, 1, 20),
                &[IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
            ),
        ];

        let error = classify_peers(input).unwrap_err().to_string();
        assert!(error.contains("exactly one exit peer"));
    }

    #[test]
    fn parses_interface_mtu_auto() {
        let path = write_temp_config(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32\n\
             MTU = auto\n\
             \n\
             [Peer]\n\
             PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
             Endpoint = 185.65.135.1:51820\n\
             AllowedIPs = 0.0.0.0/0\n",
        );

        let config = ParsedConfig::from_file(&path).unwrap();
        assert!(matches!(config.mtu, InterfaceMtu::Auto));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn renders_kernel_settings_for_supported_fields() {
        let path = write_temp_config(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32\n\
             FwMark = 1234\n\
             \n\
             [Peer]\n\
             PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25\n",
        );

        let config = ParsedConfig::from_file(&path).unwrap();
        let rendered = config.kernel_settings();

        assert!(rendered.contains("[Interface]"));
        assert!(rendered.contains("PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(rendered.contains("FwMark = 1234"));
        assert!(rendered.contains("[Peer]"));
        assert!(rendered.contains("PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="));
        assert!(rendered.contains("Endpoint = 198.51.100.1:51820"));
        assert!(rendered.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(rendered.contains("PersistentKeepalive = 25"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn renders_initial_uapi_request_for_supported_fields() {
        let path = write_temp_config(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32\n\
             FwMark = 1234\n\
             \n\
             [Peer]\n\
             PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             PersistentKeepalive = 25\n",
        );

        let config = ParsedConfig::from_file(&path).unwrap();
        let rendered = config.initial_uapi_request().unwrap();

        assert!(rendered.starts_with("set=1\n"));
        assert!(rendered.contains("private_key="));
        assert!(rendered.contains("fwmark=1234"));
        assert!(rendered.contains("replace_peers=true"));
        assert!(rendered.contains("public_key="));
        assert!(rendered.contains("endpoint=198.51.100.1:51820"));
        assert!(rendered.contains("replace_allowed_ips=true"));
        assert!(rendered.contains("allowed_ip=0.0.0.0/0"));
        assert!(rendered.contains("allowed_ip=::/0"));
        assert!(rendered.contains("persistent_keepalive_interval=25"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn renders_daita_uapi_request() {
        let path = write_temp_config(
            "[Interface]\n\
             PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             Address = 10.0.0.2/32\n\
             \n\
             [Peer]\n\
             PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 0.0.0.0/0\n",
        );

        let config = ParsedConfig::from_file(&path).unwrap();
        let private_key =
            PrivateKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let rendered = config
            .daita_uapi_request(
                &private_key,
                None,
                &DaitaSettings {
                    client_machines: vec![],
                    max_decoy_frac: 0.25,
                    max_delay_frac: 0.5,
                },
            )
            .unwrap();

        assert!(rendered.contains("daita_enable=1"));
        assert!(rendered.contains("daita_max_delayed_packets=1024"));
        assert!(rendered.contains("daita_min_delay_capacity=50"));
        assert!(rendered.contains("daita_max_decoy_frac=0.25"));
        assert!(rendered.contains("daita_max_delay_frac=0.5"));

        let _ = fs::remove_file(path);
    }

    fn write_temp_config(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("mullvad4docker-config-{unique}.conf"));
        fs::write(&path, contents).unwrap();
        path
    }
}

fn conf_line(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

fn parse_ip_list(value: &str) -> Result<Vec<IpAddr>> {
    value
        .split(',')
        .map(|item| {
            item.trim()
                .parse::<IpAddr>()
                .with_context(|| format!("invalid IP address {}", item.trim()))
        })
        .collect()
}

fn parse_interface_networks(value: &str) -> Result<Vec<IpNetwork>> {
    value
        .split(',')
        .map(|item| {
            item.trim()
                .parse::<IpNetwork>()
                .with_context(|| format!("invalid interface network {}", item.trim()))
        })
        .collect()
}

fn parse_network_list(value: &str) -> Result<Vec<IpNetwork>> {
    value
        .split(',')
        .map(|item| {
            item.trim()
                .parse::<IpNetwork>()
                .with_context(|| format!("invalid network {}", item.trim()))
        })
        .collect()
}

fn parse_preshared_key(value: &str) -> Result<PresharedKey> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("invalid base64 in preshared key")?;
    if decoded.len() != 32 {
        bail!("expected 32 bytes in preshared key, got {}", decoded.len());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(PresharedKey::from(Box::new(bytes)))
}

fn strip_comments(line: &str) -> &str {
    let mut cut_at = line.len();
    for marker in ['#', ';'] {
        if let Some(index) = line.find(marker) {
            cut_at = cut_at.min(index);
        }
    }
    &line[..cut_at]
}
