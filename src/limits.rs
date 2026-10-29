//! How often somebody may try.
//!
//! Two kinds of counting. **Per address**, where guessing would pay: creating
//! an account, joining with an enrolment token, the pairing relay — and,
//! loosely, signing in, which is counted per device at an address as well
//! (see [`crate::api::session`]). And **per account or device**, where one account holder
//! could make the server work for nobody else: pushing and pulling, making
//! tokens, opening pairing sessions, and proving the master password, which is
//! a guess too when the one proving it is not the owner. Pushes and pulls are
//! also counted **at once**, per account: how many a minute says nothing about
//! how many are held in memory at the same time.
//!
//! The counters live in memory. A restart forgets them, which is the right
//! trade for a homelab server: the alternative is a write to disk for every
//! request, to slow down an attacker who would have to survive the restart
//! anyway.

use crate::{ApiError, Result};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// What each protected endpoint allows, per address or per account.
pub struct Bucket {
    pub name: &'static str,
    pub max: usize,
    pub window: Duration,
    /// What happens to an address the limiter has no room left to remember.
    pub when_full: WhenFull,
}

/// What a bucket does with a newcomer once its table is full — once somebody
/// is making up addresses faster than they fall out of their windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFull {
    /// Let it through, uncounted: nothing here is worth guessing, and turning
    /// strangers away would turn away the devices among them too.
    Admit,
    /// Count it with its whole network — its /48, or its /24 for IPv4 — so
    /// whoever is making up addresses shares one count with themselves, and
    /// everybody else keeps a count of their own.
    Coarsen,
}

pub const ACCOUNTS: Bucket = Bucket {
    name: "accounts",
    max: 5,
    window: Duration::from_secs(60 * 60),
    when_full: WhenFull::Coarsen,
};

/// Signing in as one device, from one address. Nobody forges an Ed25519
/// signature by trying again, so this is not about guessing; it keeps the
/// requests in bounds, and it is never what keeps a device from signing in
/// when the table is full.
pub const SESSION: Bucket = Bucket {
    name: "session",
    max: 30,
    window: Duration::from_secs(60),
    when_full: WhenFull::Admit,
};

/// Signing in from one address, whichever device: loose, because an address
/// can be a whole household, a carrier's NAT, or a Docker bridge that every
/// IPv6 client comes through. It only bounds how much one address can ask.
pub const SIGN_IN: Bucket = Bucket {
    name: "sign-in",
    max: 300,
    window: Duration::from_secs(60),
    when_full: WhenFull::Admit,
};

pub const ENROL: Bucket = Bucket {
    name: "enrol",
    max: 10,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Coarsen,
};

/// Pairing is a handshake of a few messages, and the devices wait rather than
/// ask again — but they do wait in a loop, so this one is roomier.
pub const PAIR: Bucket = Bucket {
    name: "pair",
    max: 60,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Coarsen,
};

/// Signing in with UwUAuth: two requests a login, and a person who gives up
/// in the browser starts again. The second one costs a request to UwUAuth.
pub const SSO: Bucket = Bucket {
    name: "sso",
    max: 30,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Coarsen,
};

/// SCIM requests with a token that is not the one: counted only when
/// refused, so UwUAuth pushing a whole directory is never slowed down.
pub const SCIM_REFUSED: Bucket = Bucket {
    name: "scim-refused",
    max: 10,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Coarsen,
};

// ── Per account, or per device ──────────────────────────────────────────────
//
// These are never refused for want of room, so what they do when full does
// not come up.

/// A device syncing hard pushes a few batches a pass; this is room for a
/// dozen devices doing that at once.
pub const PUSH: Bucket = Bucket {
    name: "push",
    max: 120,
    window: Duration::from_secs(60),
    when_full: WhenFull::Admit,
};

/// A first pull of a large vault is a few hundred pages.
pub const PULL: Bucket = Bucket {
    name: "pull",
    max: 600,
    window: Duration::from_secs(60),
    when_full: WhenFull::Admit,
};

/// Enrolment tokens and pairing sessions: a person adds a device now and then.
pub const JOINS: Bucket = Bucket {
    name: "joins",
    max: 10,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Admit,
};

/// Everything about a team but its records: who is in it, its invites, its
/// keys. A person does these by hand; a client lists its teams on every pass.
pub const TEAMS: Bucket = Bucket {
    name: "teams",
    max: 300,
    window: Duration::from_secs(60),
    when_full: WhenFull::Admit,
};

/// Redeeming a team invite. A code is 73 bits, so this is not what keeps it
/// from being guessed — it is what keeps an account from trying. One that
/// worked does not count.
pub const TEAM_JOIN: Bucket = Bucket {
    name: "team-join",
    max: 10,
    window: Duration::from_secs(10 * 60),
    when_full: WhenFull::Admit,
};

/// Proving the master password with a device token — a password change, or
/// revoking another device. Counted **per device**: many wrong proofs are
/// somebody with a stolen device guessing, and counting them for the whole
/// account would let that device use up the owner's tries too — and keep the
/// owner from revoking it.
pub const PROOF: Bucket = Bucket {
    name: "proof",
    max: 10,
    window: Duration::from_secs(60 * 60),
    when_full: WhenFull::Admit,
};

// ── At once, per account ────────────────────────────────────────────────────

/// Requests of one kind one account may have going at the same time. A
/// bucket says how many a minute; this says how many are held in memory at
/// once — a page of records is up to 11 MiB of JSON, and it stays in memory
/// until the client has read it, which a client that never reads decides.
pub struct AtOnce {
    pub name: &'static str,
    pub max: usize,
}

/// A device pulls one page after the other; this is room for a few devices
/// of one account pulling at the same moment.
pub const PULLS: AtOnce = AtOnce {
    name: "pulls",
    max: 4,
};

/// The same for pushes, each of which may be 16 MiB while it is read.
pub const PUSHES: AtOnce = AtOnce {
    name: "pushes",
    max: 4,
};

/// How many addresses the limiter remembers at most, for each bucket on its
/// own: a flood of one endpoint fills that endpoint's table and no other.
/// Beyond that, somebody is making up addresses faster than they fall out of
/// their windows, and a newcomer is not remembered on its own any more — see
/// [`WhenFull`]. Memory stays bounded. Accounts and devices are not
/// addresses: there are only as many as the server took in, and they are
/// never refused for want of room.
const MAX_ADDRESSES: usize = 20_000;

/// Room for the networks newcomers are counted with once a table is full.
/// Beyond that too, everybody new shares a single count.
const MAX_NETWORKS: usize = 5_000;

/// The count everybody new shares once there is not even room for their
/// network.
const EVERYBODY_ELSE: &str = "everybody else";

/// How often the limiter forgets whoever is done: once a minute, and when a
/// table is full, at most once a second before it counts anybody coarser.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
const SWEEP_WHEN_FULL: Duration = Duration::from_secs(1);

type Key = (String, &'static str);

/// One address or account in one bucket.
struct Tries {
    /// When it tried, oldest first — at most `bucket.max` of them.
    at: VecDeque<Instant>,
    /// Its bucket's window: how long any of it is worth keeping.
    window: Duration,
    /// Whether the log has already heard that it was refused. A refusal is
    /// logged once, not once per request: a flood of refused requests must
    /// not become a flood of log lines on a small disk.
    said: bool,
}

#[derive(Default)]
struct Table {
    tries: HashMap<Key, Tries>,
    /// When it was last swept because it was full.
    swept_full: Option<Instant>,
}

impl Table {
    /// Forget everyone whose last try has left its bucket's window.
    fn sweep(&mut self, now: Instant) {
        self.tries.retain(|_, tries| {
            tries
                .at
                .back()
                .is_some_and(|last| now.duration_since(*last) < tries.window)
        });
    }
}

struct Hits {
    /// Addresses, a table per bucket.
    addresses: HashMap<&'static str, Table>,
    /// Accounts and devices: bounded by what the server took in, so never
    /// refused for want of room.
    members: Table,
    swept: Instant,
    /// When the log last heard that a table was full.
    said_full: Option<Instant>,
}

/// The network an address is counted with once its bucket's table is full:
/// the /48 around an IPv6 /64, which is what one site is usually given, or the
/// /24 around an IPv4 address.
fn network(who: &str) -> String {
    if let Ok(v4) = who.parse::<std::net::Ipv4Addr>() {
        let [a, b, c, _] = v4.octets();
        return format!("{a}.{b}.{c}.0/24");
    }
    if let Some(prefix) = who.strip_suffix("::/64") {
        let segments: Vec<&str> = prefix.split(':').collect();
        if let [a, b, c, _] = segments[..] {
            return format!("{a}:{b}:{c}::/48");
        }
    }
    EVERYBODY_ELSE.to_string()
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Hits>>,
    /// What each account has going right now, by kind.
    going: Arc<Mutex<HashMap<(Uuid, &'static str), usize>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Hits {
                addresses: HashMap::new(),
                members: Table::default(),
                swept: Instant::now(),
                said_full: None,
            })),
            going: Arc::default(),
        }
    }
}

/// One request an account has going, until this is dropped.
pub struct Going {
    going: Arc<Mutex<HashMap<(Uuid, &'static str), usize>>>,
    key: (Uuid, &'static str),
}

impl Drop for Going {
    fn drop(&mut self) {
        let mut going = self.going.lock();
        if let Some(count) = going.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                going.remove(&self.key);
            }
        }
    }
}

impl RateLimiter {
    /// Room for one more request of this kind from `account`, or none. The
    /// room is taken until what comes back is dropped.
    pub fn start(&self, account: Uuid, kind: &AtOnce) -> Result<Going> {
        let key = (account, kind.name);
        let mut going = self.going.lock();
        let count = going.entry(key).or_default();
        if *count >= kind.max {
            tracing::debug!(%account, kind = kind.name, "too many at once");
            return Err(ApiError::RateLimited);
        }
        *count += 1;
        Ok(Going {
            going: self.going.clone(),
            key,
        })
    }

    /// Count this attempt from an address, and say whether it is one too many.
    pub fn check(&self, who: &str, bucket: &Bucket) -> Result<()> {
        self.count(who, bucket, true)
    }

    /// Count an attempt on behalf of an account rather than an address.
    pub fn check_account(&self, account: Uuid, bucket: &Bucket) -> Result<()> {
        self.count(&format!("account:{account}"), bucket, false)
    }

    /// Count an attempt on behalf of one device.
    pub fn check_device(&self, device: Uuid, bucket: &Bucket) -> Result<()> {
        self.count(&format!("device:{device}"), bucket, false)
    }

    fn count(&self, who: &str, bucket: &Bucket, address: bool) -> Result<()> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        if now.duration_since(inner.swept) >= SWEEP_EVERY {
            for table in inner.addresses.values_mut() {
                table.sweep(now);
            }
            inner.members.sweep(now);
            inner.swept = now;
        }

        let mut key = (who.to_string(), bucket.name);
        let table = if address {
            let table = inner.addresses.entry(bucket.name).or_default();
            if !table.tries.contains_key(&key) && table.tries.len() >= MAX_ADDRESSES {
                // Before anybody is counted coarser, forget whoever is done.
                if table
                    .swept_full
                    .is_none_or(|swept| now.duration_since(swept) >= SWEEP_WHEN_FULL)
                {
                    table.sweep(now);
                    table.swept_full = Some(now);
                }
                if table.tries.len() >= MAX_ADDRESSES {
                    if inner
                        .said_full
                        .is_none_or(|said| now.duration_since(said) >= SWEEP_EVERY)
                    {
                        tracing::warn!(
                            bucket = bucket.name,
                            "the rate limiter is full; newcomers are counted by their network"
                        );
                        inner.said_full = Some(now);
                    }
                    match bucket.when_full {
                        WhenFull::Admit => return Ok(()),
                        WhenFull::Coarsen => {
                            key.0 = network(who);
                            if !table.tries.contains_key(&key)
                                && table.tries.len() >= MAX_ADDRESSES + MAX_NETWORKS
                            {
                                key.0 = EVERYBODY_ELSE.to_string();
                            }
                        }
                    }
                }
            }
            table
        } else {
            &mut inner.members
        };
        let tries = table.tries.entry(key).or_insert_with(|| Tries {
            at: VecDeque::new(),
            window: bucket.window,
            said: false,
        });
        while tries
            .at
            .front()
            .is_some_and(|first| now.duration_since(*first) >= bucket.window)
        {
            tries.at.pop_front();
        }
        if tries.at.len() >= bucket.max {
            if !tries.said {
                tracing::warn!(who, bucket = bucket.name, "rate limited");
                tries.said = true;
            }
            return Err(ApiError::RateLimited);
        }
        tries.said = false;
        tries.at.push_back(now);
        Ok(())
    }

    /// Whether an address has used up a bucket, without counting this as a
    /// try: for a bucket that counts only failures, asked before trying.
    pub fn exhausted(&self, who: &str, bucket: &Bucket) -> bool {
        let now = Instant::now();
        let inner = self.inner.lock();
        let Some(table) = inner.addresses.get(bucket.name) else {
            return false;
        };
        let key = (who.to_string(), bucket.name);
        let network = (network(who), bucket.name);
        [key, network].iter().any(|key| {
            table.tries.get(key).is_some_and(|tries| {
                tries
                    .at
                    .iter()
                    .filter(|at| now.duration_since(**at) < bucket.window)
                    .count()
                    >= bucket.max
            })
        })
    }

    /// A successful attempt need not count against the next one: the limit is
    /// there to slow down guessing, not to punish a device that syncs.
    pub fn forgive(&self, who: &str, bucket: &Bucket) {
        if let Some(table) = self.inner.lock().addresses.get_mut(bucket.name) {
            Self::take_back(table, who, bucket);
        }
    }

    pub fn forgive_account(&self, account: Uuid, bucket: &Bucket) {
        Self::take_back(
            &mut self.inner.lock().members,
            &format!("account:{account}"),
            bucket,
        );
    }

    pub fn forgive_device(&self, device: Uuid, bucket: &Bucket) {
        Self::take_back(
            &mut self.inner.lock().members,
            &format!("device:{device}"),
            bucket,
        );
    }

    fn take_back(table: &mut Table, who: &str, bucket: &Bucket) {
        if let Some(tries) = table.tries.get_mut(&(who.to_string(), bucket.name)) {
            tries.at.pop_back();
        }
    }

    #[cfg(test)]
    fn addresses(&self) -> usize {
        let inner = self.inner.lock();
        inner
            .addresses
            .values()
            .map(|table| table.tries.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: Bucket = Bucket {
        name: "tiny",
        max: 2,
        window: Duration::from_secs(60),
        when_full: WhenFull::Coarsen,
    };

    #[test]
    fn the_third_try_of_two_is_refused() {
        let limiter = RateLimiter::default();
        assert!(limiter.check("10.0.0.1", &TINY).is_ok());
        assert!(limiter.check("10.0.0.1", &TINY).is_ok());
        assert!(matches!(
            limiter.check("10.0.0.1", &TINY),
            Err(ApiError::RateLimited)
        ));
    }

    #[test]
    fn one_address_does_not_lock_out_another() {
        let limiter = RateLimiter::default();
        for _ in 0..2 {
            limiter.check("10.0.0.1", &TINY).unwrap();
        }
        assert!(limiter.check("10.0.0.2", &TINY).is_ok());
    }

    #[test]
    fn buckets_are_counted_apart() {
        let limiter = RateLimiter::default();
        for _ in 0..2 {
            limiter.check("10.0.0.1", &TINY).unwrap();
        }
        assert!(limiter.check("10.0.0.1", &ACCOUNTS).is_ok());
    }

    #[test]
    fn accounts_and_devices_are_counted_apart_from_addresses() {
        let limiter = RateLimiter::default();
        let account = Uuid::now_v7();
        for _ in 0..2 {
            limiter.check_account(account, &TINY).unwrap();
        }
        assert!(limiter.check_account(account, &TINY).is_err());
        assert!(limiter.check_account(Uuid::now_v7(), &TINY).is_ok());

        let (thief, owner) = (Uuid::now_v7(), Uuid::now_v7());
        for _ in 0..2 {
            limiter.check_device(thief, &TINY).unwrap();
        }
        assert!(limiter.check_device(thief, &TINY).is_err());
        assert!(
            limiter.check_device(owner, &TINY).is_ok(),
            "one device using up its tries leaves the others theirs"
        );
        limiter.forgive_device(thief, &TINY);
        assert!(limiter.check_device(thief, &TINY).is_ok());
    }

    #[test]
    fn what_worked_does_not_count_against_the_next_one() {
        let limiter = RateLimiter::default();
        limiter.check("10.0.0.1", &TINY).unwrap();
        limiter.forgive("10.0.0.1", &TINY);
        limiter.check("10.0.0.1", &TINY).unwrap();
        limiter.check("10.0.0.1", &TINY).unwrap();
        assert!(limiter.check("10.0.0.1", &TINY).is_err());
    }

    #[test]
    fn what_has_fallen_out_of_the_window_is_forgotten() {
        let limiter = RateLimiter::default();
        let gone = Bucket {
            name: "tiny",
            max: 1,
            window: Duration::from_millis(1),
            when_full: WhenFull::Coarsen,
        };
        limiter.check("10.0.0.1", &gone).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("10.0.0.1", &gone).is_ok());
        assert_eq!(limiter.addresses(), 1, "one address, one bucket");
    }

    /// A table of `bucket` with no room left: every one of `MAX_ADDRESSES`
    /// IPv6 networks inside 2001:db8:1::/48 has tried once.
    fn full(limiter: &RateLimiter, bucket: &Bucket) {
        for n in 0..MAX_ADDRESSES {
            limiter
                .check(&format!("2001:db8:1:{n:x}::/64"), bucket)
                .unwrap();
        }
    }

    #[test]
    fn a_flood_of_made_up_addresses_does_not_grow_without_end() {
        let limiter = RateLimiter::default();
        full(&limiter, &TINY);
        assert!(
            limiter.check("2001:db8:1:ffff::/64", &TINY).is_ok(),
            "a newcomer is counted with its network"
        );
        assert!(limiter.check("2001:db8:1:fffe::/64", &TINY).is_ok());
        assert!(
            limiter.check("2001:db8:1:fffd::/64", &TINY).is_err(),
            "and its network is the one making addresses up"
        );
        assert!(
            limiter.check("2001:db8:1:7::/64", &TINY).is_ok(),
            "whoever is known already still gets their tries"
        );
        assert!(
            limiter.check_account(Uuid::now_v7(), &PUSH).is_ok(),
            "and accounts are never refused for want of room"
        );
        assert_eq!(limiter.addresses(), MAX_ADDRESSES + 1);
    }

    #[test]
    fn a_full_table_leaves_other_networks_a_count_of_their_own() {
        let limiter = RateLimiter::default();
        full(&limiter, &ACCOUNTS);
        for _ in 0..ACCOUNTS.max {
            limiter.check("2001:db8:1:ffff::/64", &ACCOUNTS).unwrap();
        }
        assert!(limiter.check("2001:db8:1:fffe::/64", &ACCOUNTS).is_err());
        assert!(
            limiter.check("2001:db8:2:1::/64", &ACCOUNTS).is_ok(),
            "another site"
        );
        assert!(limiter.check("192.0.2.7", &ACCOUNTS).is_ok(), "IPv4");
        assert!(limiter.check("not an address", &ACCOUNTS).is_ok());

        // With no room for networks either, everybody new shares one count.
        {
            let mut inner = limiter.inner.lock();
            let table = inner.addresses.get_mut(ACCOUNTS.name).unwrap();
            for n in 0..MAX_NETWORKS {
                table.tries.insert(
                    (format!("198.51.{}.{}/24", n / 256, n % 256), ACCOUNTS.name),
                    Tries {
                        at: VecDeque::from([Instant::now()]),
                        window: ACCOUNTS.window,
                        said: false,
                    },
                );
            }
        }
        for n in 0..ACCOUNTS.max - 1 {
            assert!(limiter.check(&format!("203.0.113.{n}"), &ACCOUNTS).is_ok());
        }
        assert!(limiter.check("203.0.113.200", &ACCOUNTS).is_err());
        let most = MAX_ADDRESSES + MAX_NETWORKS + 5;
        assert!(limiter.addresses() <= most, "still bounded");
    }

    #[test]
    fn a_flood_of_one_bucket_leaves_the_others_alone() {
        let limiter = RateLimiter::default();
        full(&limiter, &ACCOUNTS);
        for bucket in [&SESSION, &ENROL, &PAIR] {
            assert!(
                limiter.check("203.0.113.9", bucket).is_ok(),
                "{}",
                bucket.name
            );
        }
    }

    #[test]
    fn signing_in_is_never_refused_for_want_of_room() {
        let limiter = RateLimiter::default();
        full(&limiter, &SESSION);
        for _ in 0..SESSION.max * 2 {
            assert!(limiter.check("2001:db8:1:ffff::/64", &SESSION).is_ok());
        }
        assert_eq!(limiter.addresses(), MAX_ADDRESSES, "and not remembered");
    }

    #[test]
    fn a_full_table_makes_room_from_whoever_is_done() {
        let limiter = RateLimiter::default();
        let brief = Bucket {
            name: "tiny",
            max: 5,
            window: Duration::from_millis(1),
            when_full: WhenFull::Coarsen,
        };
        for n in 0..MAX_ADDRESSES {
            limiter.check(&format!("key-{n}"), &brief).unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            limiter.check("newcomer", &TINY).is_ok(),
            "the ones whose short window ended made room"
        );
        assert_eq!(limiter.addresses(), 1);
        assert!(
            limiter.inner.lock().addresses["tiny"]
                .tries
                .contains_key(&("newcomer".to_string(), "tiny")),
            "and it is counted as itself"
        );
    }

    #[test]
    fn an_account_has_only_so_many_going_at_once() {
        let limiter = RateLimiter::default();
        let account = Uuid::now_v7();
        let going: Vec<_> = (0..PULLS.max)
            .map(|_| limiter.start(account, &PULLS).expect("room"))
            .collect();
        assert!(matches!(
            limiter.start(account, &PULLS),
            Err(ApiError::RateLimited)
        ));
        assert!(
            limiter.start(account, &PUSHES).is_ok(),
            "pushes are counted apart"
        );
        assert!(
            limiter.start(Uuid::now_v7(), &PULLS).is_ok(),
            "and other accounts"
        );
        drop(going);
        assert!(
            limiter.start(account, &PULLS).is_ok(),
            "done ones make room"
        );
        assert!(limiter.going.lock().is_empty(), "nothing left over");
    }
}
