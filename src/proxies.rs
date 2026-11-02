//! Which proxies are believed about where a request comes from.
//!
//! `X-Forwarded-For` and `X-Real-IP` are only headers: anybody can send them.
//! They count only when the request itself comes from a proxy the server was
//! told about (`UWUSYNC_TRUSTED_PROXIES`, or loopback and the private networks
//! without it), and then `X-Forwarded-For` is read from the right, past every
//! hop that is a trusted proxy too: the first address that is none is the
//! client. Everything left of it is the client's to make up.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network like `192.0.2.0/24` or `2001:db8::/32`; a bare address is one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `192.0.2.0/24`, `2001:db8::/32`, or a single address. Bits past the
    /// prefix are dropped.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network = canonical(address.parse::<IpAddr>().ok()?);
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) => {
                prefix.parse::<u8>().ok().filter(|prefix| *prefix <= max)?
            }
            Some(_) => return None,
            None => max,
        };
        Some(Cidr {
            network: masked(network, prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        ip.is_ipv4() == self.network.is_ipv4() && masked(ip, self.prefix) == self.network
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn masked(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// An IPv4 address as itself, not mapped into IPv6.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A list like `192.0.2.10, 198.51.100.0/24`: commas or spaces between the
/// entries.
pub fn parse_list(text: &str) -> Result<Vec<Cidr>, String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            Cidr::parse(entry).ok_or_else(|| format!("not an address or network: {entry}"))
        })
        .collect()
}

/// Where a proxy on the same machine or in the same private network comes
/// from: loopback and the private ranges (RFC 1918, unique local IPv6). What
/// `UWUSYNC_TRUST_FORWARDED=on` believes without a list.
pub fn private_networks() -> Vec<Cidr> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .into_iter()
    .map(|network| Cidr::parse(network).expect("a literal network"))
    .collect()
}

fn trusted(proxies: &[Cidr], ip: IpAddr) -> bool {
    proxies.iter().any(|network| network.contains(ip))
}

/// One entry of `X-Forwarded-For`: an address, maybe with a port.
fn hop(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    text.parse::<IpAddr>()
        .ok()
        .or_else(|| {
            text.parse::<std::net::SocketAddr>()
                .ok()
                .map(|address| address.ip())
        })
        .map(canonical)
}

/// The client behind `peer`: `peer` itself unless it is a trusted proxy,
/// otherwise the rightmost address in `X-Forwarded-For` that is no trusted
/// proxy (all of them trusted: the leftmost), or, without `X-Forwarded-For`,
/// `X-Real-IP`.
pub fn client_behind(peer: IpAddr, proxies: &[Cidr], headers: &axum::http::HeaderMap) -> IpAddr {
    let peer = canonical(peer);
    if !trusted(proxies, peer) {
        return peer;
    }
    // Every line of the header, in order: a proxy may add its own line
    // instead of appending to the client's.
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter(|value| !value.trim().is_empty())
        .collect();
    if hops.is_empty() {
        return headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(hop)
            .unwrap_or(peer);
    }
    let mut client = peer;
    for text in hops.iter().rev() {
        // Something that is no address: the hop right of it is as far as
        // anybody vouches for.
        let Some(ip) = hop(text) else { break };
        client = ip;
        if !trusted(proxies, ip) {
            break;
        }
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn networks() {
        let net = Cidr::parse("198.51.100.77/24").unwrap();
        assert_eq!(net.to_string(), "198.51.100.0/24");
        assert!(net.contains(ip("198.51.100.1")));
        assert!(
            net.contains(ip("::ffff:198.51.100.1")),
            "IPv4 mapped into IPv6 is IPv4"
        );
        assert!(!net.contains(ip("198.51.101.1")));
        assert!(!net.contains(ip("2001:db8::1")));
        let one = Cidr::parse("192.0.2.10").unwrap();
        assert!(one.contains(ip("192.0.2.10")) && !one.contains(ip("192.0.2.11")));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:1::5")) && !v6.contains(ip("2001:db9::1")));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("203.0.113.1")));
        for bad in [
            "",
            "192.0.2.0/33",
            "192.0.2.0/",
            "192.0.2.0/+8",
            "2001:db8::/129",
            "proxy.example.com",
            "192.0.2",
        ] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(
            parse_list(" 192.0.2.10, 198.51.100.0/24  2001:db8::/32 ")
                .unwrap()
                .len(),
            3
        );
        assert!(parse_list("192.0.2.10, nonsense").is_err());
    }

    #[test]
    fn only_a_trusted_proxy_is_believed() {
        let proxies = parse_list("192.0.2.10, 198.51.100.0/24").unwrap();
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.66, 203.0.113.7")]);
        // Straight from the internet: the headers are the client's own words.
        assert_eq!(
            client_behind(ip("203.0.113.50"), &proxies, &forwarded),
            ip("203.0.113.50")
        );
        assert_eq!(
            client_behind(ip("203.0.113.50"), &[], &forwarded),
            ip("203.0.113.50")
        );
        // Through the proxy: what it added last, not what the client wrote
        // before it.
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &forwarded),
            ip("203.0.113.7")
        );
        // Two proxies of ours in a row: past both.
        let chained = headers(&[("x-forwarded-for", "203.0.113.66, 203.0.113.7, 198.51.100.4")]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &chained),
            ip("203.0.113.7")
        );
        // Several header lines read as one list.
        let lines = headers(&[
            ("x-forwarded-for", "203.0.113.66"),
            ("x-forwarded-for", "203.0.113.8"),
        ]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &lines),
            ip("203.0.113.8")
        );
        // Garbage stops the walk at the last hop somebody vouched for.
        let garbage = headers(&[("x-forwarded-for", "203.0.113.66, not-an-ip, 198.51.100.4")]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &garbage),
            ip("198.51.100.4")
        );
        let only_garbage = headers(&[("x-forwarded-for", "unknown")]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &only_garbage),
            ip("192.0.2.10")
        );
        // X-Real-IP only when there is no X-Forwarded-For.
        let real = headers(&[("x-real-ip", "203.0.113.9")]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &real),
            ip("203.0.113.9")
        );
        assert_eq!(
            client_behind(ip("203.0.113.50"), &proxies, &real),
            ip("203.0.113.50")
        );
        let both = headers(&[
            ("x-real-ip", "203.0.113.9"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        assert_eq!(
            client_behind(ip("192.0.2.10"), &proxies, &both),
            ip("203.0.113.7")
        );
        // A port on a hop, IPv6 and IPv4 mapped into IPv6.
        let ported = headers(&[("x-forwarded-for", "[2001:db8::7]:4711")]);
        assert_eq!(
            client_behind(ip("::ffff:192.0.2.10"), &proxies, &ported),
            ip("2001:db8::7")
        );
    }

    #[test]
    fn the_private_networks_cover_a_proxy_next_door() {
        let private = private_networks();
        for near in [
            "127.0.0.1",
            "172.18.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "::1",
            "fd00::1",
        ] {
            assert!(trusted(&private, ip(near)), "{near}");
        }
        for far in ["203.0.113.1", "198.51.100.1", "2001:db8::1"] {
            assert!(!trusted(&private, ip(far)), "{far}");
        }
    }
}
