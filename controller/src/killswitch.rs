use anyhow::{Context, Result, bail};
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

#[derive(Clone, Copy, Debug)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
}

impl FirewallFamily {
    fn command(self) -> &'static str {
        match self {
            Self::Ipv4 => "iptables",
            Self::Ipv6 => "ip6tables",
        }
    }

    fn chain_name(self) -> &'static str {
        match self {
            Self::Ipv4 => "MULLVAD_KILLSWITCH_V4",
            Self::Ipv6 => "MULLVAD_KILLSWITCH_V6",
        }
    }

    fn destination_cidr(self, ip: &str) -> String {
        match self {
            Self::Ipv4 => format!("{ip}/32"),
            Self::Ipv6 => format!("{ip}/128"),
        }
    }
}

pub fn install(interface_name: &str, entry_endpoint: SocketAddr) -> Result<()> {
    let ipv4_entry_endpoint = match entry_endpoint.ip() {
        IpAddr::V4(ip) => Some(SocketAddr::new(IpAddr::V4(ip), entry_endpoint.port())),
        IpAddr::V6(_) => None,
    };
    install_for_family(FirewallFamily::Ipv4, interface_name, ipv4_entry_endpoint)?;

    let ipv6_entry_endpoint = match entry_endpoint.ip() {
        IpAddr::V4(_) => None,
        IpAddr::V6(ip) => Some(SocketAddr::new(IpAddr::V6(ip), entry_endpoint.port())),
    };
    install_for_family(FirewallFamily::Ipv6, interface_name, ipv6_entry_endpoint)?;

    Ok(())
}

pub fn remove_all() {
    for family in [FirewallFamily::Ipv4, FirewallFamily::Ipv6] {
        if let Err(error) = remove_for_family(family) {
            log::warn!("failed to remove {:?} kill switch chain: {error}", family);
        }
    }
}

fn install_for_family(
    family: FirewallFamily,
    interface_name: &str,
    entry_endpoint: Option<SocketAddr>,
) -> Result<()> {
    run_firewall(
        family,
        build_create_chain_args(family).iter().map(String::as_str),
    )
    .or_else(|error| {
        if error.to_string().contains("Chain already exists") {
            Ok(())
        } else {
            Err(error)
        }
    })?;

    for command in build_killswitch_install_commands(family, interface_name, entry_endpoint) {
        run_firewall(family, command.iter().map(String::as_str))?;
    }

    run_firewall(
        family,
        build_check_output_jump_args(family)
            .iter()
            .map(String::as_str),
    )
    .or_else(|_| {
        run_firewall(
            family,
            build_insert_output_jump_args(family)
                .iter()
                .map(String::as_str),
        )
    })?;

    Ok(())
}

fn remove_for_family(family: FirewallFamily) -> Result<()> {
    for command in build_killswitch_remove_commands(family) {
        let _ = run_firewall(family, command.iter().map(String::as_str));
    }
    Ok(())
}

pub fn build_create_chain_args(family: FirewallFamily) -> Vec<String> {
    vec!["-N".into(), family.chain_name().into()]
}

pub fn build_check_output_jump_args(family: FirewallFamily) -> Vec<String> {
    vec![
        "-C".into(),
        "OUTPUT".into(),
        "-j".into(),
        family.chain_name().into(),
    ]
}

pub fn build_insert_output_jump_args(family: FirewallFamily) -> Vec<String> {
    vec![
        "-I".into(),
        "OUTPUT".into(),
        "1".into(),
        "-j".into(),
        family.chain_name().into(),
    ]
}

pub fn build_killswitch_install_commands(
    family: FirewallFamily,
    interface_name: &str,
    entry_endpoint: Option<SocketAddr>,
) -> Vec<Vec<String>> {
    let chain = family.chain_name();
    let mut commands = vec![
        vec!["-F".into(), chain.into()],
        vec![
            "-A".into(),
            chain.into(),
            "-o".into(),
            "lo".into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "-A".into(),
            chain.into(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "RELATED,ESTABLISHED".into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "-A".into(),
            chain.into(),
            "-m".into(),
            "addrtype".into(),
            "--dst-type".into(),
            "LOCAL".into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "-A".into(),
            chain.into(),
            "-o".into(),
            interface_name.into(),
            "-j".into(),
            "RETURN".into(),
        ],
    ];

    if let Some(entry_endpoint) = entry_endpoint {
        commands.push(vec![
            "-A".into(),
            chain.into(),
            "-p".into(),
            "udp".into(),
            "-d".into(),
            family.destination_cidr(&entry_endpoint.ip().to_string()),
            "--dport".into(),
            entry_endpoint.port().to_string(),
            "-j".into(),
            "RETURN".into(),
        ]);
    }

    commands.push(vec![
        "-A".into(),
        chain.into(),
        "-j".into(),
        "REJECT".into(),
    ]);
    commands
}

pub fn build_killswitch_remove_commands(family: FirewallFamily) -> Vec<Vec<String>> {
    let chain = family.chain_name();
    vec![
        vec!["-D".into(), "OUTPUT".into(), "-j".into(), chain.into()],
        vec!["-F".into(), chain.into()],
        vec!["-X".into(), chain.into()],
    ]
}

fn run_firewall<'a>(family: FirewallFamily, args: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();
    let output = Command::new(family.command())
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute {} {}", family.command(), args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "{} {} failed with status {}: {}",
            family.command(),
            args.join(" "),
            output.status,
            stderr
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FirewallFamily, build_check_output_jump_args, build_create_chain_args,
        build_insert_output_jump_args, build_killswitch_install_commands,
        build_killswitch_remove_commands,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn builds_ipv4_killswitch_install_commands() {
        let commands = build_killswitch_install_commands(
            FirewallFamily::Ipv4,
            "wg0",
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                51820,
            )),
        );

        assert_eq!(commands[0], vec!["-F", "MULLVAD_KILLSWITCH_V4"]);
        assert_eq!(
            commands[1],
            vec!["-A", "MULLVAD_KILLSWITCH_V4", "-o", "lo", "-j", "RETURN"]
        );
        assert_eq!(
            commands[4],
            vec!["-A", "MULLVAD_KILLSWITCH_V4", "-o", "wg0", "-j", "RETURN"]
        );
        assert_eq!(
            commands[5],
            vec![
                "-A",
                "MULLVAD_KILLSWITCH_V4",
                "-p",
                "udp",
                "-d",
                "1.2.3.4/32",
                "--dport",
                "51820",
                "-j",
                "RETURN"
            ]
        );
        assert_eq!(
            commands[6],
            vec!["-A", "MULLVAD_KILLSWITCH_V4", "-j", "REJECT"]
        );
    }

    #[test]
    fn builds_ipv6_killswitch_install_commands_without_entry_allow_rule() {
        let commands = build_killswitch_install_commands(FirewallFamily::Ipv6, "wg0", None);

        assert_eq!(commands[0], vec!["-F", "MULLVAD_KILLSWITCH_V6"]);
        assert_eq!(
            commands.last().unwrap(),
            &vec!["-A", "MULLVAD_KILLSWITCH_V6", "-j", "REJECT"]
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.windows(2).any(|window| window == ["-d", "::1/128"]))
        );
        assert!(!commands.iter().any(|command| {
            command
                .windows(2)
                .any(|window| window == ["--dport", "51820"])
        }));
    }

    #[test]
    fn builds_ipv6_entry_destination_with_128_mask() {
        let commands = build_killswitch_install_commands(
            FirewallFamily::Ipv6,
            "wg0",
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51820)),
        );

        assert!(commands.iter().any(|command| {
            command
                == &vec![
                    "-A".to_string(),
                    "MULLVAD_KILLSWITCH_V6".to_string(),
                    "-p".to_string(),
                    "udp".to_string(),
                    "-d".to_string(),
                    "::1/128".to_string(),
                    "--dport".to_string(),
                    "51820".to_string(),
                    "-j".to_string(),
                    "RETURN".to_string(),
                ]
        }));
    }

    #[test]
    fn builds_chain_management_commands() {
        assert_eq!(
            build_create_chain_args(FirewallFamily::Ipv4),
            vec!["-N", "MULLVAD_KILLSWITCH_V4"]
        );
        assert_eq!(
            build_check_output_jump_args(FirewallFamily::Ipv4),
            vec!["-C", "OUTPUT", "-j", "MULLVAD_KILLSWITCH_V4"]
        );
        assert_eq!(
            build_insert_output_jump_args(FirewallFamily::Ipv4),
            vec!["-I", "OUTPUT", "1", "-j", "MULLVAD_KILLSWITCH_V4"]
        );
        assert_eq!(
            build_killswitch_remove_commands(FirewallFamily::Ipv4),
            vec![
                vec!["-D", "OUTPUT", "-j", "MULLVAD_KILLSWITCH_V4"],
                vec!["-F", "MULLVAD_KILLSWITCH_V4"],
                vec!["-X", "MULLVAD_KILLSWITCH_V4"],
            ]
        );
    }
}
