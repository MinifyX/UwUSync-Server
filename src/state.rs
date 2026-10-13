//! What every request has to hand.

use crate::auth::{Challenges, Sessions};
use crate::db::Db;
use crate::limits::RateLimiter;
use crate::pairing::Pairings;
use crate::Config;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<Config>,
    pub sessions: Sessions,
    pub challenges: Challenges,
    pub limits: RateLimiter,
    pub events: Events,
    pub pairings: Pairings,
    pub clock: Clock,
}

/// What time it is, for whatever runs out: a team invite, so far. The
/// system's clock, plus however far a test has moved it on — which is how a
/// test lets a week pass without waiting for it.
#[derive(Clone, Default)]
pub struct Clock {
    ahead_ms: Arc<AtomicU64>,
}

impl Clock {
    /// Milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> u64 {
        crate::now_ms().saturating_add(self.ahead_ms.load(Ordering::Relaxed))
    }

    /// Let time pass. Nothing outside tests calls this.
    pub fn advance(&self, ms: u64) {
        self.ahead_ms.fetch_add(ms, Ordering::Relaxed);
    }
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        Self {
            db: Arc::new(db),
            config: Arc::new(config),
            sessions: Sessions::default(),
            challenges: Challenges::default(),
            limits: RateLimiter::default(),
            events: Events::default(),
            pairings: Pairings::default(),
            clock: Clock::default(),
        }
    }
}

/// What a listening device is told: where to look, and nothing of what is
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum News {
    /// The account's own vault has records up to this sequence number.
    Records(u64),
    /// Something about this team changed — its records, its key, who is in
    /// it, its name — or the account's place in it did, which includes being
    /// taken out and the team being deleted.
    Team(Uuid),
}

/// "There is something new from sequence N", per account — or "look at this
/// team again".
///
/// Only the number, or the team's id, travels — a device that hears it pulls,
/// and the pull is the same one it would have made anyway. Nothing about a
/// record is ever pushed out, so this stays a hint rather than a second way in.
#[derive(Clone, Default)]
pub struct Events {
    channels: Arc<Mutex<HashMap<Uuid, broadcast::Sender<News>>>>,
    /// Open event streams per device.
    streams: Arc<Mutex<HashMap<Uuid, usize>>>,
}

/// Event streams one device may hold open. The app needs one; a few more
/// cover a restart that has not noticed the old one closing yet.
pub const MAX_STREAMS_PER_DEVICE: usize = 4;

/// An open event stream, counted until it is dropped.
pub struct StreamGuard {
    streams: Arc<Mutex<HashMap<Uuid, usize>>>,
    device: Uuid,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut streams = self.streams.lock();
        if let Some(open) = streams.get_mut(&self.device) {
            *open -= 1;
            if *open == 0 {
                streams.remove(&self.device);
            }
        }
    }
}

impl Events {
    pub fn subscribe(&self, account: Uuid) -> broadcast::Receiver<News> {
        self.channels
            .lock()
            .entry(account)
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    /// Tell whoever is listening. Nobody listening is the normal case.
    pub fn announce(&self, account: Uuid, seq: u64) {
        self.tell(account, News::Records(seq));
    }

    /// Tell every one of these accounts to look at a team again. Who they are
    /// is the caller's to know: the members, and whoever just stopped being
    /// one.
    pub fn announce_team(&self, accounts: &[Uuid], team: Uuid) {
        for account in accounts {
            self.tell(*account, News::Team(team));
        }
    }

    fn tell(&self, account: Uuid, news: News) {
        let mut channels = self.channels.lock();
        // A channel nobody listens to any more is dropped instead of kept for
        // an account that may never come back.
        if let Some(sender) = channels.get(&account) {
            if sender.receiver_count() == 0 {
                channels.remove(&account);
                return;
            }
            let _ = sender.send(news);
        }
    }

    /// Room for one more stream for this device, or none.
    pub fn open_stream(&self, device: Uuid) -> Option<StreamGuard> {
        let mut streams = self.streams.lock();
        let open = streams.entry(device).or_default();
        if *open >= MAX_STREAMS_PER_DEVICE {
            return None;
        }
        *open += 1;
        Some(StreamGuard {
            streams: self.streams.clone(),
            device,
        })
    }

    pub fn listeners(&self, account: Uuid) -> usize {
        self.channels
            .lock()
            .get(&account)
            .map(|sender| sender.receiver_count())
            .unwrap_or(0)
    }
}

/// The address a request came from, as the rate limiter counts it.
///
/// Behind a reverse proxy every request comes from the proxy, so the real
/// address is in `X-Forwarded-For` — which anyone can set, so it is only
/// believed when the server was told there is a proxy in front.
///
/// Addresses are counted the way they can be had: IPv6 per /64, because one
/// machine commonly has a whole /64 to itself and can take a fresh address
/// from it for every request.
///
/// And a forwarded address is believed only as its **last** entry: that is the one the proxy added. A
/// proxy that appends (nginx with `$proxy_add_x_forwarded_for`, most of them)
/// keeps whatever the client wrote in front of it, so the first address is the
/// client's to choose — and a rate limit keyed on it is no limit at all.
/// Anything that is not an address falls back to the socket's.
pub fn client_key(
    config: &Config,
    headers: &axum::http::HeaderMap,
    peer: Option<SocketAddr>,
) -> String {
    if config.trust_forwarded {
        // Every line of the header, in order: a proxy may add its own line
        // instead of appending to the client's.
        let last = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .rfind(|value| !value.is_empty())
            .and_then(|value| value.parse::<std::net::IpAddr>().ok());
        if let Some(address) = last {
            return counted(address);
        }
    }
    peer.map(|peer| counted(peer.ip()))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn counted(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(forwarded: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", forwarded.parse().unwrap());
        headers
    }

    #[test]
    fn a_forwarded_address_is_ignored_unless_there_is_a_proxy() {
        let config = Config::default();
        let peer = Some("10.0.0.5:4000".parse().unwrap());
        assert_eq!(
            client_key(&config, &headers("1.2.3.4"), peer),
            "10.0.0.5",
            "anyone can send that header"
        );

        let trusting = Config {
            trust_forwarded: true,
            ..Config::default()
        };
        assert_eq!(client_key(&trusting, &headers("1.2.3.4"), peer), "1.2.3.4");
        assert_eq!(
            client_key(&trusting, &headers("6.6.6.6, 1.2.3.4"), peer),
            "1.2.3.4",
            "the last one is what the proxy saw; the first is whatever the client wrote"
        );
        let mut two_lines = headers("6.6.6.6");
        two_lines.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(
            client_key(&trusting, &two_lines, peer),
            "1.2.3.4",
            "a proxy that adds a line of its own"
        );
        assert_eq!(
            client_key(&trusting, &headers("not-an-address"), peer),
            "10.0.0.5",
            "and nonsense counts as the socket"
        );
        assert_eq!(
            client_key(&trusting, &HeaderMap::new(), peer),
            "10.0.0.5",
            "and without the header, the socket"
        );
    }

    #[test]
    fn an_ipv6_machine_is_counted_once_for_its_whole_network() {
        let config = Config::default();
        let one = Some("[2001:db8:1:2::1]:4000".parse().unwrap());
        let other = Some("[2001:db8:1:2:ffff::9]:4000".parse().unwrap());
        let elsewhere = Some("[2001:db8:1:3::1]:4000".parse().unwrap());
        let key = client_key(&config, &HeaderMap::new(), one);
        assert_eq!(key, "2001:db8:1:2::/64");
        assert_eq!(client_key(&config, &HeaderMap::new(), other), key);
        assert_ne!(client_key(&config, &HeaderMap::new(), elsewhere), key);
        let mapped = Some("[::ffff:10.0.0.5]:4000".parse().unwrap());
        assert_eq!(client_key(&config, &HeaderMap::new(), mapped), "10.0.0.5");
    }

    #[test]
    fn a_device_holds_only_a_few_streams_open() {
        let events = Events::default();
        let device = Uuid::now_v7();
        let open: Vec<_> = (0..MAX_STREAMS_PER_DEVICE)
            .map(|_| events.open_stream(device).expect("room"))
            .collect();
        assert!(events.open_stream(device).is_none());
        assert!(
            events.open_stream(Uuid::now_v7()).is_some(),
            "another device"
        );
        drop(open);
        assert!(
            events.open_stream(device).is_some(),
            "closed ones make room"
        );
    }

    #[tokio::test]
    async fn an_announcement_reaches_a_listening_device() {
        let events = Events::default();
        let account = Uuid::now_v7();
        let mut listener = events.subscribe(account);
        assert_eq!(events.listeners(account), 1);

        events.announce(account, 7);
        assert_eq!(listener.recv().await.unwrap(), News::Records(7));

        let team = Uuid::now_v7();
        events.announce_team(&[Uuid::now_v7(), account], team);
        assert_eq!(listener.recv().await.unwrap(), News::Team(team));

        // Another account hears nothing.
        events.announce(Uuid::now_v7(), 9);
        assert!(listener.try_recv().is_err());
    }

    #[test]
    fn a_channel_nobody_listens_to_is_dropped() {
        let events = Events::default();
        let account = Uuid::now_v7();
        drop(events.subscribe(account));
        events.announce(account, 1);
        assert_eq!(events.listeners(account), 0);
        assert!(events.channels.lock().is_empty());
    }
}
