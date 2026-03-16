use anyhow::{Context, Result, anyhow, bail};
use std::cmp;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

pub const AUTO_MTU_WORKERS: usize = 10;
const IPV4_HEADER_LEN: u16 = 20;
const IPV6_HEADER_LEN: u16 = 40;
const UDP_HEADER_LEN: u16 = 8;
const WIREGUARD_OVERHEAD_IPV4: u16 = 60;
const WIREGUARD_OVERHEAD_IPV6: u16 = 80;
const MIN_OUTER_PATH_MTU: u16 = 1280;
const MAX_OUTER_PATH_MTU: u16 = 9000;
const PROBE_ATTEMPTS: usize = 3;
const PROBE_ATTEMPT_DELAY: Duration = Duration::from_millis(150);
const PMTUDISC_DO: libc::c_int = 2;

#[derive(Clone, Copy, Debug)]
pub struct MtuProbeResult {
    pub outer_path_mtu: u16,
    pub wireguard_overhead: u16,
    pub wireguard_mtu: u16,
}

pub fn detect_wireguard_mtu(entry_endpoint: SocketAddr) -> Result<MtuProbeResult> {
    let initial_upper_bound =
        detect_outer_path_mtu_hint(entry_endpoint)?.clamp(MIN_OUTER_PATH_MTU, MAX_OUTER_PATH_MTU);
    let outer_path_mtu =
        search_outer_path_mtu(entry_endpoint, MIN_OUTER_PATH_MTU, initial_upper_bound)?;
    let wireguard_overhead = wireguard_overhead(entry_endpoint.ip());
    let wireguard_mtu = outer_path_mtu
        .checked_sub(wireguard_overhead)
        .ok_or_else(|| {
            anyhow!(
                "detected outer path MTU {} is too small for WireGuard overhead {}",
                outer_path_mtu,
                wireguard_overhead
            )
        })?;

    Ok(MtuProbeResult {
        outer_path_mtu,
        wireguard_overhead,
        wireguard_mtu,
    })
}

fn detect_outer_path_mtu_hint(entry_endpoint: SocketAddr) -> Result<u16> {
    let socket = connect_probe_socket(entry_endpoint)?;
    current_path_mtu(&socket, entry_endpoint.ip()).or_else(|_| Ok(1500))
}

fn search_outer_path_mtu(entry_endpoint: SocketAddr, mut low: u16, mut high: u16) -> Result<u16> {
    let mut last_success = None;

    while low <= high {
        if high - low <= AUTO_MTU_WORKERS as u16 {
            for candidate in (low..=high).rev() {
                if probe_outer_path_mtu(entry_endpoint, candidate)?.succeeded {
                    return Ok(candidate);
                }
            }
            break;
        }

        let candidates = candidate_points(low, high, AUTO_MTU_WORKERS);
        let mut handles = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            handles.push(thread::spawn(move || {
                let result = probe_outer_path_mtu(entry_endpoint, candidate);
                (candidate, result)
            }));
        }

        let mut successes = Vec::new();
        let mut failures = Vec::new();
        for handle in handles {
            let (candidate, result) = handle.join().map_err(|_| {
                anyhow!("auto MTU worker panicked while probing {}", entry_endpoint)
            })?;
            let probe = result?;
            if probe.succeeded {
                successes.push(candidate);
            } else {
                failures.push(candidate);
            }
        }

        successes.sort_unstable();
        failures.sort_unstable();

        if let Some(success) = successes.last().copied() {
            last_success = Some(success);
            if success == high {
                return Ok(success);
            }
        }

        match (successes.last().copied(), failures.first().copied()) {
            (Some(success), Some(failure)) if success < failure => {
                low = success.saturating_add(1);
                high = failure.saturating_sub(1);
            }
            (Some(success), None) => {
                low = success.saturating_add(1);
            }
            (None, Some(failure)) => {
                if failure == 0 {
                    break;
                }
                high = failure.saturating_sub(1);
            }
            (Some(success), Some(_)) => {
                return Ok(success);
            }
            (None, None) => {
                bail!(
                    "auto MTU probing produced no results for {}",
                    entry_endpoint
                );
            }
        }
    }

    last_success.ok_or_else(|| anyhow!("failed to determine outer path MTU for {}", entry_endpoint))
}

#[derive(Clone, Copy, Debug)]
struct ProbeResult {
    succeeded: bool,
}

fn probe_outer_path_mtu(entry_endpoint: SocketAddr, outer_path_mtu: u16) -> Result<ProbeResult> {
    let socket = connect_probe_socket(entry_endpoint)?;
    configure_path_mtu_discovery(&socket, entry_endpoint.ip())?;

    let payload_size = outer_path_mtu
        .checked_sub(ip_header_len(entry_endpoint.ip()) + UDP_HEADER_LEN)
        .ok_or_else(|| anyhow!("outer path MTU {} is too small to probe", outer_path_mtu))?;
    let payload = vec![0u8; usize::from(payload_size)];

    for _ in 0..PROBE_ATTEMPTS {
        match socket.send(&payload) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                return Ok(ProbeResult { succeeded: false });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to send MTU probe with outer size {} to {}",
                        outer_path_mtu, entry_endpoint
                    )
                });
            }
        }

        thread::sleep(PROBE_ATTEMPT_DELAY);
        if let Ok(path_mtu) = current_path_mtu(&socket, entry_endpoint.ip()) {
            if path_mtu < outer_path_mtu {
                return Ok(ProbeResult { succeeded: false });
            }
        }
    }

    Ok(ProbeResult { succeeded: true })
}

fn connect_probe_socket(entry_endpoint: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = match entry_endpoint.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind UDP socket for MTU probe {}", entry_endpoint))?;
    socket.connect(entry_endpoint).with_context(|| {
        format!(
            "failed to connect UDP socket for MTU probe {}",
            entry_endpoint
        )
    })?;
    Ok(socket)
}

fn configure_path_mtu_discovery(socket: &UdpSocket, remote_ip: IpAddr) -> Result<()> {
    let fd = socket.as_raw_fd();
    let (level, option) = path_mtu_discover_socketopt(remote_ip)?;

    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &PMTUDISC_DO as *const _ as *const libc::c_void,
            mem::size_of_val(&PMTUDISC_DO) as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return Err(error).context("failed to enable PMTU discovery on MTU probe socket");
    }

    Ok(())
}

fn current_path_mtu(socket: &UdpSocket, remote_ip: IpAddr) -> Result<u16> {
    let fd = socket.as_raw_fd();
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    let (level, option) = current_path_mtu_socketopt(remote_ip)?;

    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return Err(error).context("failed to query path MTU from probe socket");
    }
    if value <= 0 {
        bail!("kernel reported invalid path MTU {}", value);
    }

    Ok(value as u16)
}

fn wireguard_overhead(remote_ip: IpAddr) -> u16 {
    match remote_ip {
        IpAddr::V4(_) => WIREGUARD_OVERHEAD_IPV4,
        IpAddr::V6(_) => WIREGUARD_OVERHEAD_IPV6,
    }
}

fn ip_header_len(remote_ip: IpAddr) -> u16 {
    match remote_ip {
        IpAddr::V4(_) => IPV4_HEADER_LEN,
        IpAddr::V6(_) => IPV6_HEADER_LEN,
    }
}

fn candidate_points(low: u16, high: u16, workers: usize) -> Vec<u16> {
    if low >= high || workers <= 1 {
        return vec![high];
    }

    let span = u32::from(high - low);
    let desired = cmp::min(workers, (span + 1) as usize);
    if desired == 1 {
        return vec![low];
    }

    let mut points = Vec::with_capacity(desired);
    for index in 0..desired {
        let candidate = low + ((span * index as u32) / (desired.saturating_sub(1) as u32)) as u16;
        if points.last().copied() != Some(candidate) {
            points.push(candidate);
        }
    }
    points
}

#[cfg(target_os = "linux")]
fn path_mtu_discover_socketopt(remote_ip: IpAddr) -> Result<(libc::c_int, libc::c_int)> {
    Ok(match remote_ip {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
    })
}

#[cfg(not(target_os = "linux"))]
fn path_mtu_discover_socketopt(_remote_ip: IpAddr) -> Result<(libc::c_int, libc::c_int)> {
    bail!("auto MTU probing is only supported on Linux");
}

#[cfg(target_os = "linux")]
fn current_path_mtu_socketopt(remote_ip: IpAddr) -> Result<(libc::c_int, libc::c_int)> {
    Ok(match remote_ip {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MTU),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MTU),
    })
}

#[cfg(not(target_os = "linux"))]
fn current_path_mtu_socketopt(_remote_ip: IpAddr) -> Result<(libc::c_int, libc::c_int)> {
    bail!("auto MTU probing is only supported on Linux");
}

#[cfg(test)]
mod tests {
    use super::{AUTO_MTU_WORKERS, candidate_points, wireguard_overhead};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn candidate_points_cover_range_edges() {
        let points = candidate_points(1280, 1500, AUTO_MTU_WORKERS);
        assert_eq!(points.first().copied(), Some(1280));
        assert_eq!(points.last().copied(), Some(1500));
        assert!(points.len() <= AUTO_MTU_WORKERS);
    }

    #[test]
    fn candidate_points_return_full_small_ranges() {
        assert_eq!(
            candidate_points(1280, 1284, AUTO_MTU_WORKERS),
            vec![1280, 1281, 1282, 1283, 1284]
        );
    }

    #[test]
    fn wireguard_overhead_depends_on_outer_ip_family() {
        assert_eq!(wireguard_overhead(IpAddr::V4(Ipv4Addr::LOCALHOST)), 60);
        assert_eq!(wireguard_overhead(IpAddr::V6(Ipv6Addr::LOCALHOST)), 80);
    }
}
