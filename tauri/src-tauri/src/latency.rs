use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub const PINGS_PER_LOCATION: usize = 3;
pub const PING_TIMEOUT: Duration = Duration::from_millis(1_500);
pub const PING_CONCURRENCY: usize = 4;
pub const MAX_PING_TARGETS: usize = 200;

const MAGIC: [u8; 4] = [0x4d, 0x4e, 0x54, 0x50];
const VERSION: u8 = 1;
const NONCE_OFFSET: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub id: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Measurement {
    pub id: String,
    pub samples: Vec<Option<f64>>,
}

pub fn ping_request(nonce: &[u8; 16]) -> [u8; 32] {
    let mut packet = [0u8; 32];
    packet[..4].copy_from_slice(&MAGIC);
    packet[4] = VERSION;
    packet[5] = 1;
    packet[NONCE_OFFSET..NONCE_OFFSET + 16].copy_from_slice(nonce);
    packet
}

pub fn is_ping_reply(packet: &[u8], nonce: &[u8; 16]) -> bool {
    packet.len() == 24 && packet[..4] == MAGIC && packet[4] == VERSION && packet[5] == 2 && packet[6] == 0 && packet[7] == 0 && &packet[NONCE_OFFSET..NONCE_OFFSET + 16] == nonce
}

async fn address_of(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.ok()?.collect();
    addresses.iter().find(|address| address.is_ipv4()).or(addresses.first()).copied()
}

async fn ping_once(socket: &UdpSocket, address: SocketAddr) -> Option<f64> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    let started = Instant::now();
    socket.send_to(&ping_request(&nonce), address).await.ok()?;
    let mut buffer = [0u8; 64];
    let wait = async {
        loop {
            let (read, _) = socket.recv_from(&mut buffer).await.ok()?;
            if is_ping_reply(&buffer[..read], &nonce) {
                return Some(started.elapsed().as_secs_f64() * 1000.0);
            }
        }
    };
    tokio::time::timeout(PING_TIMEOUT.saturating_sub(started.elapsed()), wait).await.ok().flatten()
}

pub async fn measure_target(target: Target) -> Measurement {
    let empty = Measurement { id: target.id.clone(), samples: vec![None; PINGS_PER_LOCATION] };
    let Some(address) = address_of(&target.host, target.port).await else { return empty };
    let bind: SocketAddr = if address.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let Ok(socket) = UdpSocket::bind(bind).await else { return empty };
    let mut samples = Vec::with_capacity(PINGS_PER_LOCATION);
    for _ in 0..PINGS_PER_LOCATION {
        samples.push(ping_once(&socket, address).await);
    }
    Measurement { id: target.id, samples }
}

pub async fn measure_targets(targets: Vec<Target>) -> Vec<Measurement> {
    let mut results = Vec::with_capacity(targets.len());
    for chunk in targets.chunks(PING_CONCURRENCY) {
        let handles: Vec<_> = chunk.iter().cloned().map(|target| tokio::spawn(measure_target(target))).collect();
        for (handle, target) in handles.into_iter().zip(chunk) {
            results.push(handle.await.unwrap_or(Measurement { id: target.id.clone(), samples: vec![None; PINGS_PER_LOCATION] }));
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_match_shared_protocol() {
        let nonce = [7u8; 16];
        let request = ping_request(&nonce);
        assert_eq!(&request[..8], &[0x4d, 0x4e, 0x54, 0x50, 1, 1, 0, 0]);
        assert_eq!(&request[8..24], &nonce);
        let mut reply = [0u8; 24];
        reply[..4].copy_from_slice(&MAGIC);
        reply[4] = 1;
        reply[5] = 2;
        reply[8..24].copy_from_slice(&nonce);
        assert!(is_ping_reply(&reply, &nonce));
        assert!(!is_ping_reply(&reply, &[8u8; 16]));
        reply[5] = 1;
        assert!(!is_ping_reply(&reply, &nonce));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn measures_against_a_local_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            while let Ok((read, from)) = echo.recv_from(&mut buffer).await {
                if read != 32 {
                    continue;
                }
                let mut reply = [0u8; 24];
                reply[..4].copy_from_slice(&MAGIC);
                reply[4] = 1;
                reply[5] = 2;
                reply[8..24].copy_from_slice(&buffer[8..24]);
                let _ = echo.send_to(&reply, from).await;
            }
        });
        let results = measure_targets(vec![
            Target { id: "a".into(), host: "127.0.0.1".into(), port },
            Target { id: "b".into(), host: "256.0.0.1".into(), port },
        ])
        .await;
        assert_eq!(results[0].id, "a");
        assert!(results[0].samples.iter().all(Option::is_some));
        assert_eq!(results[1].samples, vec![None; 3]);
    }
}
