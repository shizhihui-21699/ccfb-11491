//! Beaconing analysis over decoded flow records.
//!
//! A beacon is an internal host that calls out on a near-constant schedule.
//! Records are aggregated on the full 5-tuple key (`(src, dst, sport, dport,
//! proto)`) so that different conversations to the same C2 are not blended.
//!
//! ## Threshold rationale
//!
//! Real networks produce two failure modes the detector must survive:
//! * **Jitter** — the callback is not perfectly clocked (sleep granularity,
//!   GC pauses, network latency). We measure jitter with the *median absolute
//!   deviation* (MAD), which is robust to a handful of large deviations,
//!   rather than the standard deviation, which a single missed callback can
//!   inflate enough to hide a beacon.
//! * **Missed callbacks** — one dropped flow makes two intervals double-wide.
//!   MAD absorbs up to ~30% contaminated samples; the plain coefficient of
//!   variation is kept as a secondary, stricter signal.
//!
//! A pair is flagged when **all** of the following hold:
//! 1. at least `MIN_SAMPLES` (6) end timestamps observed,
//! 2. median interval within [`MIN_INTERVAL_MS`, `MAX_INTERVAL_MS`]
//!    (5 s … 2 h) — excludes sub-second chatter and effectively-dormant
//!    pairs,
//! 3. robust jitter ratio (MAD / median) ≤ 0.35,
//! 4. composite periodicity score ≥ 60 / 100.
//!
//! Whitelisted heartbeat protocols (NTP, DNS, …) are still tracked and shown
//! but never flagged.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::protocol::FlowRecord;

/// Minimum callbacks before any verdict is emitted.
pub const MIN_SAMPLES: usize = 6;
/// Ignore intervals shorter than this (burst/chatter, not a schedule).
pub const MIN_INTERVAL_MS: u64 = 5_000;
/// Ignore intervals longer than this (2 h; effectively dormant pairs).
pub const MAX_INTERVAL_MS: u64 = 2 * 60 * 60 * 1000;
/// Robust jitter ceiling: MAD must stay within 35 % of the median interval.
pub const JITTER_LIMIT: f64 = 0.35;
/// Composite score required for a BEACON verdict.
pub const SCORE_LIMIT: f64 = 60.0;
/// Rolling window of timestamps retained per pair.
const WINDOW: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PairKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Clone, Debug)]
pub struct PairStats {
    pub key: PairKey,
    /// Sorted end timestamps (ms epoch), newest WINDOW kept.
    times: Vec<i64>,
    pub total_bytes: u64,
    pub total_records: u64,
    pub last_seen_ms: i64,
}

impl PairStats {
    fn new(key: PairKey, rec: &FlowRecord) -> Self {
        PairStats {
            key,
            times: vec![rec.end_ms],
            total_bytes: rec.bytes,
            total_records: 1,
            last_seen_ms: rec.end_ms,
        }
    }

    fn add(&mut self, rec: &FlowRecord) {
        self.total_records += 1;
        self.total_bytes = self.total_bytes.saturating_add(rec.bytes);
        self.last_seen_ms = self.last_seen_ms.max(rec.end_ms);
        // Insert sorted; duplicate timestamps (multiple flows ending in the
        // same millisecond) are dropped — intervals must be positive.
        match self.times.binary_search(&rec.end_ms) {
            Ok(_) => {}
            Err(pos) => self.times.insert(pos, rec.end_ms),
        }
        if self.times.len() > WINDOW {
            self.times.remove(0);
        }
    }
}

/// Verdict + the measurements that produced it, all exported to JSON.
#[derive(Clone, Debug)]
pub struct Metrics {
    pub samples: usize,
    pub intervals: usize,
    pub median_interval_ms: u64,
    pub mean_interval_ms: u64,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    /// Standard deviation / mean (0 when only one interval exists).
    pub cv: f64,
    /// Median absolute deviation / median — the robust jitter measure.
    pub robust_cv: f64,
    pub score: f64,
    pub verdict: Verdict,
    pub whitelisted: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Beacon,
    Candidate,
    Insufficient,
    Aperiodic,
    Whitelisted,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Beacon => "BEACON",
            Verdict::Candidate => "candidate",
            Verdict::Aperiodic => "aperiodic",
            Verdict::Insufficient => "warming-up",
            Verdict::Whitelisted => "whitelisted",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PairReport {
    pub key: PairKey,
    pub total_records: u64,
    pub total_bytes: u64,
    pub last_seen_ms: i64,
    pub metrics: Metrics,
}

pub struct Analyzer {
    pairs: HashMap<PairKey, PairStats>,
    /// UDP/TCP ports considered normal heartbeat traffic (either direction).
    whitelist_ports: Vec<u16>,
    /// L4 protocol numbers whitelisted wholesale (e.g. 1 = ICMP).
    whitelist_protos: Vec<u8>,
}

impl Analyzer {
    pub fn new(whitelist_ports: Vec<u16>, whitelist_protos: Vec<u8>) -> Self {
        Analyzer {
            pairs: HashMap::new(),
            whitelist_ports,
            whitelist_protos,
        }
    }

    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    pub fn add_record(&mut self, rec: &FlowRecord) {
        let key = PairKey {
            src_ip: rec.src_ip,
            dst_ip: rec.dst_ip,
            src_port: rec.src_port,
            dst_port: rec.dst_port,
            protocol: rec.protocol,
        };
        match self.pairs.get_mut(&key) {
            Some(stats) => stats.add(rec),
            None => {
                self.pairs.insert(key, PairStats::new(key, rec));
            }
        }
    }

    fn is_whitelisted(&self, key: &PairKey) -> bool {
        if self.whitelist_protos.contains(&key.protocol) {
            return true;
        }
        self.whitelist_ports.contains(&key.dst_port) || self.whitelist_ports.contains(&key.src_port)
    }

    /// Compute metrics for every pair and sort: beacons first (score desc),
    /// then the rest by observed record count desc.
    pub fn reports(&self) -> Vec<PairReport> {
        let mut reports: Vec<_> = self
            .pairs
            .values()
            .map(|stats| {
                let whitelisted = self.is_whitelisted(&stats.key);
                PairReport {
                    key: stats.key,
                    total_records: stats.total_records,
                    total_bytes: stats.total_bytes,
                    last_seen_ms: stats.last_seen_ms,
                    metrics: analyze_intervals(&stats.times, whitelisted),
                }
            })
            .collect();
        reports.sort_by(|a, b| {
            use std::cmp::Ordering;
            match (
                a.metrics.verdict == Verdict::Beacon,
                b.metrics.verdict == Verdict::Beacon,
            ) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => b
                    .metrics
                    .score
                    .partial_cmp(&a.metrics.score)
                    .unwrap_or(Ordering::Equal)
                    .then(b.total_records.cmp(&a.total_records)),
            }
        });
        reports
    }
}

fn analyze_intervals(times: &[i64], whitelisted: bool) -> Metrics {
    let samples = times.len();
    let mut intervals: Vec<u64> = times
        .windows(2)
        .map(|w| (w[1] - w[0]).max(0) as u64)
        .filter(|&d| d > 0)
        .collect();
    intervals.sort_unstable();

    let mut m = Metrics {
        samples,
        intervals: intervals.len(),
        median_interval_ms: 0,
        mean_interval_ms: 0,
        min_interval_ms: 0,
        max_interval_ms: 0,
        cv: 0.0,
        robust_cv: 0.0,
        score: 0.0,
        verdict: Verdict::Insufficient,
        whitelisted,
        reasons: Vec::new(),
    };

    if intervals.is_empty() {
        if whitelisted {
            m.verdict = Verdict::Whitelisted;
        }
        return m;
    }

    let n = intervals.len();
    m.min_interval_ms = intervals[0];
    m.max_interval_ms = intervals[n - 1];
    let sum: u128 = intervals.iter().map(|&x| x as u128).sum();
    let mean = (sum / n as u128) as u64;
    m.mean_interval_ms = mean;
    let median = if n % 2 == 1 {
        intervals[n / 2]
    } else {
        (intervals[n / 2 - 1] / 2)
            + (intervals[n / 2] / 2)
            + (intervals[n / 2 - 1] % 2 + intervals[n / 2] % 2) / 2
    };
    m.median_interval_ms = median;

    // Classical coefficient of variation (secondary signal).
    if n >= 2 && mean > 0 {
        let var: f64 = intervals
            .iter()
            .map(|&x| {
                let d = x as f64 - mean as f64;
                d * d
            })
            .sum::<f64>()
            / (n - 1) as f64;
        m.cv = var.sqrt() / mean as f64;
    }

    // Robust jitter: MAD / median, scaled by 1.4826 so it is comparable to a
    // standard deviation under Gaussian jitter.
    if median > 0 {
        let devs: Vec<f64> = intervals
            .iter()
            .map(|&x| (x as i64 - median as i64).unsigned_abs() as f64)
            .collect();
        let mut sorted = devs;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mad = if sorted.len() % 2 == 1 {
            sorted[sorted.len() / 2]
        } else {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        };
        m.robust_cv = (mad * 1.4826) / median as f64;
    }

    // ---- composite score (0..100) --------------------------------------
    // Robust jitter contributes 60 points: 0% jitter -> 60, >=100% -> 0.
    let jitter_pts = (60.0 * (1.0 - m.robust_cv.min(1.0))).max(0.0);
    // Classical CV contributes 25 points (stricter, catches wide spreads
    // that MAD tolerates too well).
    let cv_pts = (25.0 * (1.0 - m.cv.min(1.0))).max(0.0);
    // Sample confidence contributes 15 points, saturating at 20 intervals.
    let sample_pts = 15.0 * (n.min(20) as f64 / 20.0);
    m.score = (jitter_pts + cv_pts + sample_pts).min(100.0);

    // ---- verdict --------------------------------------------------------
    if whitelisted {
        m.verdict = Verdict::Whitelisted;
        return m;
    }
    if samples < MIN_SAMPLES {
        m.verdict = Verdict::Insufficient;
        m.reasons
            .push(format!("only {samples} samples (< {MIN_SAMPLES})"));
        return m;
    }
    if median < MIN_INTERVAL_MS {
        m.verdict = Verdict::Aperiodic;
        m.reasons.push(format!(
            "median interval {}ms below {}ms floor",
            median, MIN_INTERVAL_MS
        ));
        return m;
    }
    if median > MAX_INTERVAL_MS {
        m.verdict = Verdict::Aperiodic;
        m.reasons.push(format!(
            "median interval {}ms above {}ms ceiling",
            median, MAX_INTERVAL_MS
        ));
        return m;
    }
    if m.robust_cv > JITTER_LIMIT {
        m.verdict = Verdict::Aperiodic;
        m.reasons.push(format!(
            "robust jitter {:.1}% exceeds {:.0}% limit",
            m.robust_cv * 100.0,
            JITTER_LIMIT * 100.0
        ));
        return m;
    }
    if m.score >= SCORE_LIMIT {
        m.verdict = Verdict::Beacon;
        m.reasons.push(format!(
            "period ~{:.1}s, robust jitter {:.1}%, score {:.0}",
            median as f64 / 1000.0,
            m.robust_cv * 100.0,
            m.score
        ));
    } else {
        m.verdict = Verdict::Candidate;
        m.reasons
            .push(format!("score {:.0} below {:.0}", m.score, SCORE_LIMIT));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rec(ts_ms: i64, dport: u16, bytes: u64) -> FlowRecord {
        FlowRecord {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            src_port: 40000,
            dst_port: dport,
            protocol: 6,
            bytes,
            end_ms: ts_ms,
        }
    }

    fn build(times: &[i64], dport: u16) -> Analyzer {
        let mut a = Analyzer::new(vec![53, 123], vec![1]);
        for t in times {
            a.add_record(&rec(*t, dport, 100));
        }
        a
    }

    #[test]
    fn perfect_period_is_beacon() {
        let times: Vec<i64> = (0..12).map(|i| i * 60_000).collect();
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_eq!(r.metrics.verdict, Verdict::Beacon);
        assert_eq!(r.metrics.median_interval_ms, 60_000);
        assert!(r.metrics.robust_cv < 0.05);
    }

    #[test]
    fn jittery_beacon_still_detected() {
        // 60 s period ± up to 12 s jitter (~20 %), one doubled interval.
        let jitter = [0, 4_000, -7_000, 3_000, -11_000, 9_000, -2_000, 6_000];
        let mut times = vec![0i64];
        let mut t = 0i64;
        for (i, j) in jitter.iter().enumerate() {
            t += 60_000 + j;
            if i == 4 {
                t += 60_000; // missed callback: one 2x gap
            }
            times.push(t);
        }
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_eq!(
            r.metrics.verdict,
            Verdict::Beacon,
            "reasons: {:?}",
            r.metrics.reasons
        );
    }

    #[test]
    fn random_traffic_is_aperiodic() {
        let mut times = vec![0i64];
        // Pseudo-random gaps with no periodic structure (fixed LCG so the
        // test is deterministic).
        let mut seed = 42u64;
        for _ in 0..20 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let gap = 5_000 + (seed % 120_000) as i64;
            times.push(times.last().unwrap() + gap);
        }
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_ne!(r.metrics.verdict, Verdict::Beacon);
    }

    #[test]
    fn whitelisted_ports_never_flag() {
        let times: Vec<i64> = (0..12).map(|i| i * 60_000).collect();
        let a = build(&times, 123); // NTP
        let r = &a.reports()[0];
        assert_eq!(r.metrics.verdict, Verdict::Whitelisted);
    }

    #[test]
    fn warming_up_needs_enough_samples() {
        let times: Vec<i64> = (0..4).map(|i| i * 60_000).collect();
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_eq!(r.metrics.verdict, Verdict::Insufficient);
    }

    #[test]
    fn high_jitter_is_rejected() {
        // Alternating 30 s / 90 s gaps: median still 60 s, but MAD/median is
        // ~74 % — well over the 35 % robust-jitter ceiling.
        let mut times = vec![0i64];
        for i in 0..12 {
            let gap = if i % 2 == 0 { 30_000 } else { 90_000 };
            times.push(times.last().unwrap() + gap);
        }
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_eq!(r.metrics.median_interval_ms, 60_000);
        assert!(r.metrics.robust_cv > JITTER_LIMIT);
        assert_eq!(r.metrics.verdict, Verdict::Aperiodic);
    }

    #[test]
    fn sub_five_second_chatter_is_rejected() {
        // Perfectly regular 1 s polling: periodic in shape but under the
        // interval floor, so it must not be called a beacon.
        let times: Vec<i64> = (0..12).map(|i| i * 1_000).collect();
        let a = build(&times, 443);
        let r = &a.reports()[0];
        assert_eq!(r.metrics.verdict, Verdict::Aperiodic);
        assert!(r.metrics.reasons.iter().any(|x| x.contains("below")));
    }
}
