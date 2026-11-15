//! Manual JSON serialization — no serde, keeps the build offline-capable.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::analyzer::{PairReport, Verdict};
use crate::protocol::ParserStats;

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn ip_string(ip: IpAddr) -> String {
    ip.to_string()
}

/// Render the full report as a JSON string. `generated_ms` is the wall clock
/// at export time; `uptime_ms` is how long the collector has been running.
pub fn render_json(
    reports: &[PairReport],
    parser_stats: &ParserStats,
    pending: usize,
    generated_ms: i64,
    uptime_ms: u64,
) -> String {
    let mut s = String::with_capacity(4096 + reports.len() * 512);
    s.push_str("{\n");
    s.push_str(&format!("  \"generated_ms\": {generated_ms},\n"));
    s.push_str(&format!("  \"uptime_ms\": {uptime_ms},\n"));
    s.push_str("  \"collector\": {\n");
    s.push_str(&format!("    \"packets\": {},\n", parser_stats.packets));
    s.push_str(&format!("    \"flowsets\": {},\n", parser_stats.flowsets));
    s.push_str(&format!(
        "    \"data_flowsets\": {},\n",
        parser_stats.data_flowsets
    ));
    s.push_str(&format!("    \"records\": {},\n", parser_stats.records));
    s.push_str(&format!(
        "    \"records_buffered\": {},\n",
        parser_stats.records_buffered
    ));
    s.push_str(&format!(
        "    \"records_replayed\": {},\n",
        parser_stats.records_replayed
    ));
    s.push_str(&format!(
        "    \"templates_seen\": {},\n",
        parser_stats.templates_seen
    ));
    s.push_str(&format!("    \"pending_flowsets\": {},\n", pending));
    s.push_str(&format!(
        "    \"pending_overflow\": {},\n",
        parser_stats.pending_overflow
    ));
    s.push_str(&format!(
        "    \"records_incomplete\": {},\n",
        parser_stats.records_incomplete
    ));
    s.push_str(&format!(
        "    \"decode_errors\": {}\n",
        parser_stats.decode_errors
    ));
    s.push_str("  },\n");

    let beacon_count = reports
        .iter()
        .filter(|r| r.metrics.verdict == Verdict::Beacon)
        .count();
    s.push_str(&format!("  \"beacon_count\": {beacon_count},\n"));
    s.push_str(&format!("  \"pair_count\": {},\n", reports.len()));
    s.push_str("  \"pairs\": [\n");

    for (i, r) in reports.iter().enumerate() {
        s.push_str("    {\n");
        s.push_str(&format!(
            "      \"src_ip\": {},\n",
            json_str(&ip_string(r.key.src_ip))
        ));
        s.push_str(&format!(
            "      \"dst_ip\": {},\n",
            json_str(&ip_string(r.key.dst_ip))
        ));
        s.push_str(&format!("      \"src_port\": {},\n", r.key.src_port));
        s.push_str(&format!("      \"dst_port\": {},\n", r.key.dst_port));
        s.push_str(&format!("      \"protocol\": {},\n", r.key.protocol));
        s.push_str(&format!("      \"records\": {},\n", r.total_records));
        s.push_str(&format!("      \"bytes\": {},\n", r.total_bytes));
        s.push_str(&format!("      \"last_seen_ms\": {},\n", r.last_seen_ms));
        s.push_str("      \"metrics\": {\n");
        s.push_str(&format!(
            "        \"verdict\": {},\n",
            json_str(r.metrics.verdict.label())
        ));
        s.push_str(&format!(
            "        \"whitelisted\": {},\n",
            r.metrics.whitelisted
        ));
        s.push_str(&format!("        \"samples\": {},\n", r.metrics.samples));
        s.push_str(&format!(
            "        \"intervals\": {},\n",
            r.metrics.intervals
        ));
        s.push_str(&format!(
            "        \"median_interval_ms\": {},\n",
            r.metrics.median_interval_ms
        ));
        s.push_str(&format!(
            "        \"mean_interval_ms\": {},\n",
            r.metrics.mean_interval_ms
        ));
        s.push_str(&format!(
            "        \"min_interval_ms\": {},\n",
            r.metrics.min_interval_ms
        ));
        s.push_str(&format!(
            "        \"max_interval_ms\": {},\n",
            r.metrics.max_interval_ms
        ));
        s.push_str(&format!("        \"cv\": {:.4},\n", r.metrics.cv));
        s.push_str(&format!(
            "        \"robust_cv\": {:.4},\n",
            r.metrics.robust_cv
        ));
        s.push_str(&format!("        \"score\": {:.1},\n", r.metrics.score));
        s.push_str("        \"reasons\": [");
        for (j, reason) in r.metrics.reasons.iter().enumerate() {
            if j > 0 {
                s.push_str(", ");
            }
            escape(reason, &mut s);
        }
        s.push_str("]\n");
        s.push_str("      }\n");
        s.push_str("    }");
        if i + 1 < reports.len() {
            s.push(',');
        }
        s.push('\n');
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

fn json_str(raw: &str) -> String {
    let mut s = String::new();
    escape(raw, &mut s);
    s
}

/// Atomically write the report: write to `<path>.tmp` then rename, so a
/// reader never observes a half-written file.
pub fn write_json(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    {
        let f = File::create(&tmp)?;
        let mut w = BufWriter::new(f);
        w.write_all(contents.as_bytes())?;
        w.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
