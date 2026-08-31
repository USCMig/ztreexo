//! Resource limits for a bridge that faces something other than a test.
//!
//! # The threat, stated concretely
//!
//! CLAUDE.md Phase 6 asks for "cost to a bridge node of a peer requesting
//! proofs for every UTXO; rate limiting and proof-size caps". Measuring that
//! turned up a cheaper attack than requesting 27.5M proofs.
//!
//! **The bridge is single-threaded by construction.** `ChainAccumulators` holds
//! `Rc`/`Weak` with interior mutability, so it is not `Send`
//! (`docs/design.md` D27); concurrency has to come from owning the state on one
//! thread. That is a design constraint, not an oversight — but it means
//! *serving is a single queue*, and until now nothing bounded how long one
//! request could sit at the head of it.
//!
//! A client that opens a TCP connection and sends one byte of an HTTP header,
//! then nothing, blocks `read_request` in a `read()` that never returns. Not
//! for a while: **forever**, and for every other client at the same time. One
//! socket, no traffic, no CPU. That is slowloris, and against a single-threaded
//! server it is total rather than degrading.
//!
//! So the first limit here is a timeout, and it matters more than the byte
//! caps that were already in place.
//!
//! # What these do not do
//!
//! No TLS and no authentication. These limits make a bridge survivable on a
//! trusted network; they do not make it safe on a hostile one. The module docs
//! on [`server`](crate::server) still say bind it to loopback, and they still
//! mean it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Caps applied to every connection a bridge serves.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How long a single `read` may block.
    ///
    /// **The load-bearing one.** Without it a silent client parks the only
    /// serving thread indefinitely.
    pub read_timeout: Duration,
    /// How long a single `write` may block. A client that stops reading its
    /// response fills the socket buffer and stalls the server otherwise —
    /// slowloris in the other direction.
    pub write_timeout: Duration,
    /// Total wall clock for one request, across however many reads it takes.
    ///
    /// A per-read timeout alone is not enough: a client can send one byte just
    /// inside every deadline and hold the queue forever at negligible cost.
    pub request_deadline: Duration,
    /// Largest header block accepted.
    pub max_header_bytes: usize,
    /// Largest request body accepted, checked before allocating.
    pub max_body_bytes: usize,
    /// Largest response the bridge will serialise and send.
    ///
    /// A cap on *our* output, not the client's input: a bundle for a
    /// sandblasted block runs to hundreds of kilobytes, and Phase 5b measured
    /// individual blocks near 471 KB.
    pub max_response_bytes: usize,
    /// Requests allowed per source address per minute. Zero disables it.
    pub requests_per_minute: u32,
    /// How many source addresses to track before evicting the least recently
    /// seen. Bounds the limiter's own memory, which is otherwise a way to
    /// attack the thing meant to prevent attacks.
    pub max_tracked_peers: usize,
    /// Bytes of cohort payload one address may pull per minute. Zero disables.
    ///
    /// # Why counting requests is not enough
    ///
    /// The two limits guard different resources and the request counter is the
    /// wrong instrument for this one. A cohort at the operating point is
    /// **384.9 KB** (`docs/design.md` D38), so a peer sitting politely inside
    /// `requests_per_minute` of 600 pulls 231 MB a minute — from a
    /// single-threaded bridge, on a link it does not pay for. Every other
    /// response this server sends is orders of magnitude smaller, which is why
    /// nothing needed a byte budget until cohorts existed.
    ///
    /// Charged on *actual* serialised bytes, after the cohort is built. The
    /// CPU spent building it is bounded by the request counter instead; a
    /// budget cannot refuse work whose size it does not yet know without
    /// guessing, and a guess that runs low would refuse honest clients.
    pub cohort_bytes_per_minute: u64,
}

impl Default for Limits {
    /// Deliberately strict. A local sidecar never notices these; anything that
    /// does is doing something this server was not built for.
    fn default() -> Limits {
        Limits {
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            request_deadline: Duration::from_secs(30),
            max_header_bytes: 16 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            // Comfortably above the largest bundle Phase 5b measured, and far
            // below anything that would strain a client.
            max_response_bytes: 8 * 1024 * 1024,
            requests_per_minute: 600,
            max_tracked_peers: 4096,
            // 64 MiB is ~170 cohorts a minute at the measured size. A wallet
            // resolving its whole note set does tens of queries per sync and
            // D41 says to *spread* them rather than burst, so this is generous
            // for any client following the privacy guidance and tight against
            // one that is not.
            cohort_bytes_per_minute: 64 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// No rate limiting, generous timeouts — for tests that drive the socket
    /// by hand and would otherwise flake on a slow machine.
    pub fn permissive() -> Limits {
        Limits {
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            request_deadline: Duration::from_secs(120),
            requests_per_minute: 0,
            cohort_bytes_per_minute: 0,
            ..Limits::default()
        }
    }
}

/// One peer's token buckets: one counting requests, one counting bytes.
///
/// Both live in the same entry so a peer occupies one map slot rather than
/// two — otherwise the eviction cap in [`Limits::max_tracked_peers`] would
/// mean half as many peers as it says.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    bytes: f64,
    last: Instant,
    /// Separate from `last` because the two buckets refill on independent
    /// clocks: a peer that makes cheap requests must not thereby refill its
    /// byte allowance, and vice versa.
    last_bytes: Instant,
}

/// Per-address token-bucket rate limiter.
///
/// # Why a bucket rather than a counter per window
///
/// A fixed window lets a client spend its whole allowance in the last instant
/// of one window and again in the first of the next, so the real peak is twice
/// the configured rate. A bucket refills continuously and has no such edge.
///
/// Uses `Instant`, which CLAUDE.md §5 rule 5 bans from anything touching a
/// root. Nothing here does: rate limiting decides whether to answer, never what
/// the answer is, so two bridges under different load still produce identical
/// roots and identical proofs.
#[derive(Debug)]
pub struct RateLimiter {
    per_minute: u32,
    bytes_per_minute: u64,
    capacity: usize,
    peers: BTreeMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// A limiter allowing `limits.requests_per_minute` per address.
    pub fn new(limits: &Limits) -> RateLimiter {
        RateLimiter {
            per_minute: limits.requests_per_minute,
            bytes_per_minute: limits.cohort_bytes_per_minute,
            capacity: limits.max_tracked_peers.max(1),
            peers: BTreeMap::new(),
        }
    }

    /// How many addresses are currently tracked.
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }

    /// Whether `peer` may make a request now, spending a token if so.
    pub fn allow(&mut self, peer: IpAddr) -> bool {
        self.allow_at(peer, Instant::now())
    }

    /// The same, with the clock supplied — so the behaviour can be tested
    /// without sleeping, which is the difference between a test that pins the
    /// refill rate and a test that pins nothing.
    pub fn allow_at(&mut self, peer: IpAddr, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let burst = f64::from(self.per_minute);
        let refill_per_sec = burst / 60.0;

        // Evict before inserting, so the map cannot exceed its cap even for an
        // instant. Least-recently-seen: a flood of new addresses pushes out
        // other new addresses rather than a long-lived legitimate peer.
        if !self.peers.contains_key(&peer) && self.peers.len() >= self.capacity {
            if let Some(&oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, bucket)| bucket.last)
                .map(|(address, _)| address)
            {
                self.peers.remove(&oldest);
            }
        }

        let byte_burst = self.bytes_per_minute as f64;
        let bucket = self.peers.entry(peer).or_insert(Bucket {
            tokens: burst,
            bytes: byte_burst,
            last: now,
            last_bytes: now,
        });

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether `peer` may be sent `bytes` of cohort payload now, spending the
    /// budget if so.
    ///
    /// Called with the response already serialised, so a refusal here costs the
    /// bridge the work and saves it the bandwidth. That is the right way round:
    /// bandwidth is the scarce resource a cohort consumes, and the CPU is
    /// already bounded by [`RateLimiter::allow`].
    pub fn allow_bytes(&mut self, peer: IpAddr, bytes: u64) -> bool {
        self.allow_bytes_at(peer, bytes, Instant::now())
    }

    /// The same, with the clock supplied.
    pub fn allow_bytes_at(&mut self, peer: IpAddr, bytes: u64, now: Instant) -> bool {
        if self.bytes_per_minute == 0 {
            return true;
        }
        let burst = self.bytes_per_minute as f64;
        let refill_per_sec = burst / 60.0;

        if !self.peers.contains_key(&peer) && self.peers.len() >= self.capacity {
            if let Some(&oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, bucket)| bucket.last.min(bucket.last_bytes))
                .map(|(address, _)| address)
            {
                self.peers.remove(&oldest);
            }
        }

        let requests = f64::from(self.per_minute);
        let bucket = self.peers.entry(peer).or_insert(Bucket {
            tokens: requests,
            bytes: burst,
            last: now,
            last_bytes: now,
        });

        let elapsed = now
            .saturating_duration_since(bucket.last_bytes)
            .as_secs_f64();
        bucket.bytes = (bucket.bytes + elapsed * refill_per_sec).min(burst);
        bucket.last_bytes = now;

        let cost = bytes as f64;
        // A single response larger than the whole budget would otherwise be
        // unservable forever, no matter how long the peer waited. Refusing it
        // is correct — the budget is the operator's statement about what this
        // bridge will emit — but it must be a refusal, not a stall.
        if cost > bucket.bytes {
            return false;
        }
        bucket.bytes -= cost;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn limiter(per_minute: u32) -> RateLimiter {
        RateLimiter::new(&Limits {
            requests_per_minute: per_minute,
            ..Limits::default()
        })
    }

    #[test]
    fn a_burst_is_allowed_then_refused() {
        let mut limiter = limiter(60);
        let now = Instant::now();
        for i in 0..60 {
            assert!(
                limiter.allow_at(ip(1), now),
                "request {i} refused inside the burst"
            );
        }
        assert!(
            !limiter.allow_at(ip(1), now),
            "the 61st request was allowed"
        );
    }

    #[test]
    fn tokens_refill_with_time() {
        let mut limiter = limiter(60);
        let start = Instant::now();
        for _ in 0..60 {
            assert!(limiter.allow_at(ip(1), start));
        }
        assert!(!limiter.allow_at(ip(1), start));

        // 60/minute is one per second.
        assert!(limiter.allow_at(ip(1), start + Duration::from_secs(1)));
        assert!(!limiter.allow_at(ip(1), start + Duration::from_secs(1)));
    }

    #[test]
    fn refill_does_not_exceed_the_burst() {
        // An idle hour must not buy an hour's worth of requests at once.
        let mut limiter = limiter(60);
        let start = Instant::now();
        assert!(limiter.allow_at(ip(1), start));
        let later = start + Duration::from_secs(3600);
        for _ in 0..60 {
            assert!(limiter.allow_at(ip(1), later));
        }
        assert!(
            !limiter.allow_at(ip(1), later),
            "an idle peer accumulated more than one burst"
        );
    }

    #[test]
    fn peers_are_limited_independently() {
        let mut limiter = limiter(2);
        let now = Instant::now();
        assert!(limiter.allow_at(ip(1), now));
        assert!(limiter.allow_at(ip(1), now));
        assert!(!limiter.allow_at(ip(1), now));
        // A different address is unaffected, or one noisy peer would deny
        // everyone — which is the attack, not the defence.
        assert!(limiter.allow_at(ip(2), now));
        assert!(limiter.allow_at(ip(2), now));
    }

    #[test]
    fn tracking_is_bounded_so_the_limiter_is_not_itself_a_target() {
        let mut limiter = RateLimiter::new(&Limits {
            requests_per_minute: 10,
            max_tracked_peers: 8,
            ..Limits::default()
        });
        let start = Instant::now();
        for i in 0..200u8 {
            limiter.allow_at(ip(i), start + Duration::from_millis(u64::from(i)));
        }
        assert!(
            limiter.tracked() <= 8,
            "tracked {} addresses against a cap of 8",
            limiter.tracked()
        );
    }

    #[test]
    fn the_byte_budget_refuses_a_peer_the_request_counter_would_wave_through() {
        // The reason the second bucket exists. At the default 600 requests a
        // minute and D38's 384.9 KB cohort, a peer inside the request limit
        // pulls 231 MB — so the counter alone is not a bandwidth control.
        let mut limiter = RateLimiter::new(&Limits {
            requests_per_minute: 600,
            cohort_bytes_per_minute: 1_000_000,
            ..Limits::default()
        });
        let now = Instant::now();
        let cohort = 384_900u64;

        for i in 0..2 {
            assert!(limiter.allow_at(ip(1), now), "request {i} refused");
            assert!(
                limiter.allow_bytes_at(ip(1), cohort, now),
                "bytes {i} refused"
            );
        }
        // The third cohort is 1,154,700 bytes cumulative against a 1 MB budget.
        assert!(
            limiter.allow_at(ip(1), now),
            "the request counter still has 597 tokens, so it must allow this"
        );
        assert!(
            !limiter.allow_bytes_at(ip(1), cohort, now),
            "the byte budget must refuse what the request counter allows"
        );
    }

    #[test]
    fn the_byte_budget_refills_on_its_own_clock() {
        // Not on the request bucket's. A peer making cheap calls must not
        // thereby refill its cohort allowance, and a peer spending bytes must
        // not lose its cheap calls.
        let mut limiter = RateLimiter::new(&Limits {
            requests_per_minute: 60,
            cohort_bytes_per_minute: 600,
            ..Limits::default()
        });
        let start = Instant::now();
        assert!(limiter.allow_bytes_at(ip(1), 600, start));
        assert!(!limiter.allow_bytes_at(ip(1), 1, start));

        // Spending request tokens must not move the byte bucket.
        for _ in 0..10 {
            assert!(limiter.allow_at(ip(1), start));
        }
        assert!(
            !limiter.allow_bytes_at(ip(1), 1, start),
            "cheap requests refilled the byte budget"
        );

        // 600/minute is 10 bytes a second.
        assert!(limiter.allow_bytes_at(ip(1), 10, start + Duration::from_secs(1)));
        assert!(!limiter.allow_bytes_at(ip(1), 1, start + Duration::from_secs(1)));
    }

    #[test]
    fn a_response_larger_than_the_whole_budget_is_refused_rather_than_stalling() {
        // Waiting would never help: the bucket caps at one minute's worth, so
        // a response above that is unservable no matter how long the peer
        // idles. It has to be a refusal the client can see.
        let mut limiter = RateLimiter::new(&Limits {
            cohort_bytes_per_minute: 1_000,
            ..Limits::default()
        });
        let start = Instant::now();
        assert!(!limiter.allow_bytes_at(ip(1), 5_000, start));
        assert!(
            !limiter.allow_bytes_at(ip(1), 5_000, start + Duration::from_secs(3600)),
            "an hour of idling must not buy more than one burst"
        );
        // And it did not consume the budget on the way to refusing.
        assert!(limiter.allow_bytes_at(ip(1), 1_000, start));
    }

    #[test]
    fn byte_budgets_are_per_peer() {
        let mut limiter = RateLimiter::new(&Limits {
            cohort_bytes_per_minute: 100,
            ..Limits::default()
        });
        let now = Instant::now();
        assert!(limiter.allow_bytes_at(ip(1), 100, now));
        assert!(!limiter.allow_bytes_at(ip(1), 1, now));
        assert!(
            limiter.allow_bytes_at(ip(2), 100, now),
            "one greedy peer must not deny everyone — that is the attack"
        );
    }

    #[test]
    fn a_peer_occupies_one_slot_whichever_bucket_it_touches() {
        // Both buckets share an entry. If they did not, `max_tracked_peers`
        // would mean half what it says and the limiter's own memory bound
        // would be wrong.
        let mut limiter = RateLimiter::new(&Limits {
            requests_per_minute: 10,
            cohort_bytes_per_minute: 1_000,
            max_tracked_peers: 8,
            ..Limits::default()
        });
        let start = Instant::now();
        for i in 0..200u8 {
            let at = start + Duration::from_millis(u64::from(i));
            limiter.allow_at(ip(i), at);
            limiter.allow_bytes_at(ip(i), 1, at);
        }
        assert!(
            limiter.tracked() <= 8,
            "tracked {} addresses against a cap of 8",
            limiter.tracked()
        );
    }

    #[test]
    fn a_zero_byte_budget_disables_only_the_byte_budget() {
        let mut limiter = RateLimiter::new(&Limits {
            requests_per_minute: 2,
            cohort_bytes_per_minute: 0,
            ..Limits::default()
        });
        let now = Instant::now();
        for _ in 0..1_000 {
            assert!(limiter.allow_bytes_at(ip(1), u64::MAX, now));
        }
        // The request counter is untouched by that.
        assert!(limiter.allow_at(ip(1), now));
        assert!(limiter.allow_at(ip(1), now));
        assert!(!limiter.allow_at(ip(1), now));
    }

    #[test]
    fn zero_disables_the_limiter() {
        let mut limiter = limiter(0);
        let now = Instant::now();
        for _ in 0..10_000 {
            assert!(limiter.allow_at(ip(1), now));
        }
        assert_eq!(
            limiter.tracked(),
            0,
            "a disabled limiter should track nothing"
        );
    }
}
