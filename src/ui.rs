//! Terminal dashboard.
//!
//! On a TTY the screen is redrawn in place once per second using ANSI cursor
//! control. When stdout is not a TTY (piped to a file, journald, …) it
//! degrades to one compact summary line per tick so logs stay greppable.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analyzer::{PairReport, Verdict};
use crate::protocol::ParserStats;

const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_CYAN: &str = "\x1b[36m";
const ANSI_RESET: &str = "\x1b[0m";

const MAX_ROWS: usize = 20;

pub struct Ui {
    tty: bool,
    first_draw: bool,
}

impl Ui {
    pub fn new(tty: bool) -> Self {
        Ui {
            tty,
            first_draw: true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &mut self,
        out: &mut impl Write,
        reports: &[PairReport],
        stats: &ParserStats,
        pending: usize,
        bind: &str,
        uptime_ms: u64,
        auto_export: Option<&str>,
        notice: Option<&str>,
    ) {
        if self.tty {
            self.draw_tty(
                out,
                reports,
                stats,
                pending,
                bind,
                uptime_ms,
                auto_export,
                notice,
            );
        } else {
            self.draw_line(out, reports, stats, pending, uptime_ms);
            if let Some(n) = notice {
                let _ = writeln!(out, "NOTICE {n}");
            }
        }
        self.first_draw = false;
        let _ = out.flush();
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_tty(
        &mut self,
        out: &mut impl Write,
        reports: &[PairReport],
        stats: &ParserStats,
        pending: usize,
        bind: &str,
        uptime_ms: u64,
        auto_export: Option<&str>,
        notice: Option<&str>,
    ) {
        let mut buf = String::new();
        buf.push_str(ANSI_CLEAR);
        buf.push_str(&format!(
            "{ANSI_BOLD}beacon-hunter{ANSI_RESET}  listening on udp://{bind}  uptime {}\n",
            fmt_duration(uptime_ms)
        ));
        buf.push_str(&format!(
            "packets {p}  flowsets {fs}  records {r}  buffered {b}  replayed {rp}  pending-flowsets {pe}  decode-errors {e}\n",
            p = stats.packets,
            fs = stats.flowsets,
            r = stats.records,
            b = stats.records_buffered,
            rp = stats.records_replayed,
            pe = pending,
            e = stats.decode_errors,
        ));
        let beacons = reports
            .iter()
            .filter(|r| r.metrics.verdict == Verdict::Beacon)
            .count();
        let candidates = reports
            .iter()
            .filter(|r| r.metrics.verdict == Verdict::Candidate)
            .count();
        let export_note = auto_export
            .map(|p| format!("  auto-export -> {p}"))
            .unwrap_or_default();
        buf.push_str(&format!(
            "pairs {n}  {ANSI_RED}{ANSI_BOLD}beacons {b}{ANSI_RESET}  {ANSI_YELLOW}candidates {c}{ANSI_RESET}{note}\n",
            n = reports.len(),
            b = beacons,
            c = candidates,
            note = export_note,
        ));
        if let Some(n) = notice {
            buf.push_str(&format!("{ANSI_GREEN}{n}{ANSI_RESET}\n"));
        }
        buf.push_str(&format!(
            "{ANSI_DIM}[q] quit+export  [e] export now  Ctrl-C also exports{ANSI_RESET}\n\n"
        ));

        // Header
        buf.push_str(&format!(
            "{ANSI_BOLD}{:<23} {:<23} {:<5} {:<6} {:>5} {:>9} {:>8} {:>6}  {:<10}{ANSI_RESET}\n",
            "SRC", "DST", "PROTO", "DPORT", "HITS", "PERIOD(s)", "JIT%", "SCORE", "VERDICT"
        ));

        for r in reports.iter().take(MAX_ROWS) {
            let period = r.metrics.median_interval_ms as f64 / 1000.0;
            let jit = r.metrics.robust_cv * 100.0;
            let (color, dim) = match r.metrics.verdict {
                Verdict::Beacon => (ANSI_RED, false),
                Verdict::Candidate => (ANSI_YELLOW, false),
                Verdict::Whitelisted => (ANSI_DIM, true),
                Verdict::Aperiodic => (ANSI_GREEN, false),
                Verdict::Insufficient => (ANSI_CYAN, false),
            };
            let dim_prefix = if dim { ANSI_DIM } else { "" };
            buf.push_str(&format!(
                "{dp}{color}{:<23} {:<23} {:<5} {:<6} {:>5} {:>9.1} {:>7.1}% {:>6.0}  {:<10}{ANSI_RESET}\n",
                fmt_pair_ip(r.key.src_ip, r.key.src_port),
                fmt_pair_ip(r.key.dst_ip, r.key.dst_port),
                proto_name(r.key.protocol),
                r.key.dst_port,
                r.total_records,
                period,
                jit,
                r.metrics.score,
                r.metrics.verdict.label(),
                dp = dim_prefix,
            ));
        }
        if reports.len() > MAX_ROWS {
            buf.push_str(&format!(
                "{ANSI_DIM}... {} more pairs (full detail in JSON export){ANSI_RESET}\n",
                reports.len() - MAX_ROWS
            ));
        }
        let _ = out.write_all(buf.as_bytes());
    }

    /// Non-TTY mode: one machine-greppable line per tick.
    fn draw_line(
        &mut self,
        out: &mut impl Write,
        reports: &[PairReport],
        stats: &ParserStats,
        pending: usize,
        uptime_ms: u64,
    ) {
        let beacons = reports
            .iter()
            .filter(|r| r.metrics.verdict == Verdict::Beacon)
            .count();
        let line = format!(
            "[{t}] uptime={up} packets={p} records={r} buffered={b} replayed={rp} pending={pe} pairs={n} beacons={bc} errors={e}\n",
            t = fmt_wall(),
            up = fmt_duration(uptime_ms),
            p = stats.packets,
            r = stats.records,
            b = stats.records_buffered,
            rp = stats.records_replayed,
            pe = pending,
            n = reports.len(),
            bc = beacons,
            e = stats.decode_errors,
        );
        let _ = out.write_all(line.as_bytes());
        // Announce each newly present beacon on its own line.
        if self.first_draw {
            for r in reports
                .iter()
                .filter(|r| r.metrics.verdict == Verdict::Beacon)
            {
                let _ = writeln!(
                    out,
                    "BEACON {} -> {} proto={} dport={} period={:.1}s jit={:.1}% score={:.0}",
                    r.key.src_ip,
                    r.key.dst_ip,
                    proto_name(r.key.protocol),
                    r.key.dst_port,
                    r.metrics.median_interval_ms as f64 / 1000.0,
                    r.metrics.robust_cv * 100.0,
                    r.metrics.score,
                );
            }
        }
    }
}

fn fmt_pair_ip(ip: std::net::IpAddr, port: u16) -> String {
    let s = ip.to_string();
    if s.len() > 21 {
        format!("[{s}]:{port}")
    } else {
        format!("{s}:{port}")
    }
    .chars()
    .take(23)
    .collect()
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "other",
    }
}

fn fmt_duration(ms: u64) -> String {
    let s = ms / 1000;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}h{m:02}m{sec:02}s")
    } else {
        format!("{m}m{sec:02}s")
    }
}

fn fmt_wall() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // UTC, no timezone database in std.
    let secs_of_day = now % 86400;
    format!(
        "{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}
