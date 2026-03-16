use anyhow::{Context, Result, anyhow, bail};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UapiClient {
    socket_path: PathBuf,
}

impl UapiClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn set(&self, request: &str) -> Result<String> {
        self.send_request(request)
    }

    pub fn get(&self) -> Result<String> {
        self.send_request("get=1\n\n")
    }

    pub fn send_request(&self, request: &str) -> Result<String> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "failed to connect to WireGuard UAPI socket {}",
                self.socket_path.display()
            )
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .context("failed to set UAPI read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .context("failed to set UAPI write timeout")?;

        let request = ensure_protocol_termination(request);
        stream.write_all(request.as_bytes()).with_context(|| {
            format!(
                "failed to write UAPI request to {}",
                self.socket_path.display()
            )
        })?;
        let _ = stream.shutdown(std::net::Shutdown::Write);

        let mut response = String::new();
        stream.read_to_string(&mut response).with_context(|| {
            format!(
                "failed to read UAPI response from {}",
                self.socket_path.display()
            )
        })?;

        let errno = parse_errno(&response)?;
        if errno != 0 {
            bail!(
                "UAPI request failed with errno {} on {}: {}",
                errno,
                self.socket_path.display(),
                compact_response(&response)
            );
        }

        Ok(response)
    }
}

fn ensure_protocol_termination(request: &str) -> String {
    if request.ends_with("\n\n") {
        request.to_string()
    } else {
        format!("{}\n\n", request.trim_end_matches('\n'))
    }
}

fn parse_errno(response: &str) -> Result<i32> {
    response
        .lines()
        .find_map(|line| line.strip_prefix("errno="))
        .ok_or_else(|| {
            anyhow!(
                "missing errno in UAPI response: {}",
                compact_response(response)
            )
        })?
        .parse::<i32>()
        .context("failed to parse errno from UAPI response")
}

fn compact_response(response: &str) -> String {
    response.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{ensure_protocol_termination, parse_errno};

    #[test]
    fn appends_uapi_terminator() {
        assert_eq!(
            ensure_protocol_termination("set=1\nfoo=bar"),
            "set=1\nfoo=bar\n\n"
        );
        assert_eq!(ensure_protocol_termination("get=1\n\n"), "get=1\n\n");
    }

    #[test]
    fn parses_errno_from_response() {
        assert_eq!(parse_errno("public_key=abc\nerrno=0\n").unwrap(), 0);
        assert_eq!(parse_errno("errno=22\n").unwrap(), 22);
    }
}
