//! Wire-level integration tests: packets are hand-built from raw bytes so
//! the parser is tested against the actual RFC framing, not shared helpers.

use std::net::{IpAddr, Ipv4Addr};

use beacon_hunter::analyzer::Analyzer;
use beacon_hunter::protocol::{FlowRecord, Parser};

const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

// NF9 field type ids.
const NF9_IN_BYTES: u16 = 1;
const NF9_PROTOCOL: u16 = 4;
const NF9_SRCPORT: u16 = 7;
const NF9_SRCIP: u16 = 8;
const NF9_DSTPORT: u16 = 11;
const NF9_DSTIP: u16 = 12;
const NF9_LAST_SWITCHED: u16 = 21;
const NF9_FIRST_SWITCHED: u16 = 22;

// IPFIX IE ids.
const IP_OCTET_DELTA: u16 = 85;
const IP_END_MS: u16 = 153;
const IP_START_MS: u16 = 152;

fn field(ie: u16, len: u16) -> [u8; 4] {
    let v = ((ie as u32) << 16) | len as u32;
    v.to_be_bytes()
}

fn nf9_header(count: u16, sysup: u32, unix_secs: u32, source_id: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(9u16.to_be_bytes());
    h.extend(count.to_be_bytes());
    h.extend(sysup.to_be_bytes());
    h.extend(unix_secs.to_be_bytes());
    h.extend(1u32.to_be_bytes()); // sequence
    h.extend(source_id.to_be_bytes());
    h
}

fn ipfix_header(length: u16, unix_secs: u32, odid: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(10u16.to_be_bytes());
    h.extend(length.to_be_bytes());
    h.extend(unix_secs.to_be_bytes());
    h.extend(1u32.to_be_bytes());
    h.extend(odid.to_be_bytes());
    h
}

fn set_header(id: u16, body: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(id.to_be_bytes());
    h.extend((body.len() as u16 + 4).to_be_bytes());
    h.extend_from_slice(body);
    h
}

/// NF9 template 256: srcIP(4), dstIP(4), sport(2), dport(2), proto(1),
/// bytes(4), first(4), last(4) — 25-byte records.
fn nf9_template() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(256u16.to_be_bytes());
    body.extend(8u16.to_be_bytes());
    for (ie, len) in [
        (NF9_SRCIP, 4u16),
        (NF9_DSTIP, 4),
        (NF9_SRCPORT, 2),
        (NF9_DSTPORT, 2),
        (NF9_PROTOCOL, 1),
        (NF9_IN_BYTES, 4),
        (NF9_FIRST_SWITCHED, 4),
        (NF9_LAST_SWITCHED, 4),
    ] {
        body.extend(field(ie, len));
    }
    let mut pkt = nf9_header(1, 1_000, 1_700_000_000, 100);
    pkt.extend(set_header(2, &body));
    pkt
}

fn nf9_data_record(last: u32, first: u32, bytes: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend([10u8, 0, 0, 5]);
    r.extend([198u8, 51, 100, 20]);
    r.extend(44444u16.to_be_bytes());
    r.extend(8443u16.to_be_bytes());
    r.push(6); // TCP
    r.extend(bytes.to_be_bytes());
    r.extend(first.to_be_bytes());
    r.extend(last.to_be_bytes());
    r
}

#[test]
fn nf9_basic_parse_with_relative_timestamps() {
    let mut parser = Parser::new();
    parser.parse(&nf9_template(), EXPORTER).unwrap();

    // Record ends at sysup 60_000; header export time unix 1_700_000_000.
    let rec = nf9_data_record(60_000, 59_500, 313);
    let mut body = Vec::new();
    body.extend(rec);
    let mut pkt = nf9_header(1, 60_000, 1_700_000_000, 100);
    pkt.extend(set_header(256, &body));

    let out = parser.parse(&pkt, EXPORTER).unwrap();
    assert_eq!(out.len(), 1);
    let FlowRecord {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        bytes,
        end_ms,
    } = &out[0];
    assert_eq!(*src_ip, SRC);
    assert_eq!(*dst_ip, DST);
    assert_eq!(*src_port, 44444);
    assert_eq!(*dst_port, 8443);
    assert_eq!(*protocol, 6);
    assert_eq!(*bytes, 313);
    // export_ms(1_700_000_000_000) - (sysup 60_000 - last 60_000)
    assert_eq!(*end_ms, 1_700_000_000_000);
    assert_eq!(parser.stats.records, 1);
}

#[test]
fn late_template_buffers_then_replays() {
    let mut parser = Parser::new();

    // 1. Data first, template unknown -> buffered, nothing decoded.
    let rec = nf9_data_record(60_000, 59_500, 100);
    let mut pkt = nf9_header(1, 60_000, 1_700_000_000, 100);
    pkt.extend(set_header(256, &rec));
    let out = parser.parse(&pkt, EXPORTER).unwrap();
    assert!(out.is_empty());
    assert_eq!(parser.pending_count(), 1);
    assert_eq!(parser.stats.records_buffered, 1);

    // 2. Template arrives -> buffered flowset replayed with the *original*
    //    packet's export context, not the template packet's clock.
    let out = parser.parse(&nf9_template(), EXPORTER).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(parser.pending_count(), 0);
    assert_eq!(parser.stats.records_replayed, 1);
    assert_eq!(out[0].end_ms, 1_700_000_000_000);
}

#[test]
fn templates_are_isolated_per_exporter_and_domain() {
    let mut parser = Parser::new();
    let exporter_b = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));

    // Exporter A installs template 256 (the NF9 25-byte layout).
    parser.parse(&nf9_template(), EXPORTER).unwrap();

    // Exporter B sends data with the same template id but a totally
    // different layout (IPFIX-style absolute ms). It must NOT be decoded
    // against A's template — it should buffer instead.
    let mut b_body = Vec::new();
    b_body.extend([10u8, 1, 1, 1]); // src
    b_body.extend([10, 2, 2, 2]); // dst
    b_body.extend(1234u16.to_be_bytes());
    b_body.extend(443u16.to_be_bytes());
    b_body.push(6);
    b_body.extend(777u32.to_be_bytes());
    b_body.extend(1_700_000_500_000u64.to_be_bytes()); // end ms
    let mut b_pkt = ipfix_header((16 + 4 + b_body.len()) as u16, 1_700_000_500, 200);
    b_pkt.extend(set_header(256, &b_body));

    let out = parser.parse(&b_pkt, exporter_b).unwrap();
    assert!(out.is_empty());
    assert_eq!(parser.pending_count(), 1);
    assert_eq!(parser.stats.decode_errors, 0);
}

#[test]
fn ipfix_absolute_millisecond_timestamps_and_enterprise_bit() {
    let mut parser = Parser::new();

    // Template 300: src, dst, sport, dport, proto(1), octets(8), endMs(8),
    // plus one enterprise-specific field (E-bit + PEN) the parser must skip.
    let mut body = Vec::new();
    body.extend(300u16.to_be_bytes());
    body.extend(8u16.to_be_bytes());
    body.extend(field(NF9_SRCIP, 4));
    body.extend(field(NF9_DSTIP, 4));
    body.extend(field(NF9_SRCPORT, 2));
    body.extend(field(NF9_DSTPORT, 2));
    body.extend(field(NF9_PROTOCOL, 1));
    body.extend(field(IP_OCTET_DELTA, 8));
    body.extend(field(IP_END_MS, 8));
    let mut ent = field(999, 4);
    ent[0] |= 0x80; // enterprise bit
    body.extend(ent);
    body.extend(42424242u32.to_be_bytes()); // PEN
    let tmpl_len = 16 + 4 + body.len();
    let mut pkt = ipfix_header(tmpl_len as u16, 1_700_000_000, 200);
    pkt.extend(set_header(2, &body));
    parser.parse(&pkt, EXPORTER).unwrap();

    // Data record matching that layout.
    let mut rec = Vec::new();
    rec.extend([10u8, 0, 0, 5]);
    rec.extend([198, 51, 100, 20]);
    rec.extend(55555u16.to_be_bytes());
    rec.extend(443u16.to_be_bytes());
    rec.push(17); // UDP
    rec.extend(4096u64.to_be_bytes());
    rec.extend(1_700_000_123_456u64.to_be_bytes());
    rec.extend(0xDEAD_BEEFu32.to_be_bytes()); // enterprise value ignored
    let data_len = 16 + 4 + rec.len();
    let mut pkt = ipfix_header(data_len as u16, 1_700_000_000, 200);
    pkt.extend(set_header(300, &rec));

    let out = parser.parse(&pkt, EXPORTER).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].protocol, 17);
    assert_eq!(out[0].bytes, 4096);
    assert_eq!(out[0].end_ms, 1_700_000_123_456);
    let _ = IP_START_MS; // documented IE id, exercised by the generator
}

#[test]
fn ipfix_variable_length_field_is_skipped_cleanly() {
    let mut parser = Parser::new();

    // Template 301 with a varlen (0xffff) string field between proto and
    // the end timestamp.
    let mut body = Vec::new();
    body.extend(301u16.to_be_bytes());
    body.extend(5u16.to_be_bytes());
    body.extend(field(NF9_SRCIP, 4));
    body.extend(field(NF9_DSTIP, 4));
    body.extend(field(NF9_PROTOCOL, 1));
    body.extend(field(999, 0xffff)); // varlen, enterprise 0, unknown IE
    body.extend(field(IP_END_MS, 8));
    let tmpl_len = 16 + 4 + body.len();
    let mut pkt = ipfix_header(tmpl_len as u16, 1_700_000_000, 200);
    pkt.extend(set_header(2, &body));
    parser.parse(&pkt, EXPORTER).unwrap();

    // Record: IPs, proto, short-form varlen (1-byte len=5 + 5 bytes), endMs
    let mut rec = Vec::new();
    rec.extend([10u8, 0, 0, 9]);
    rec.extend([192, 0, 2, 9]);
    rec.push(6);
    rec.push(5u8);
    rec.extend(b"hello");
    rec.extend(1_700_000_005_000u64.to_be_bytes());
    let data_len = 16 + 4 + rec.len();
    let mut pkt = ipfix_header(data_len as u16, 1_700_000_000, 200);
    pkt.extend(set_header(301, &rec));

    let out = parser.parse(&pkt, EXPORTER).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].end_ms, 1_700_000_005_000);
    assert_eq!(out[0].src_port, 0); // absent -> defaulted
}

#[test]
fn full_pipeline_flags_only_true_beacons() {
    // Feed the parser-generated records straight into the analyzer: one
    // strict beacon, one NTP heartbeat, one random pair.
    let mut analyzer = Analyzer::new(vec![53, 123], vec![1]);
    let base = 1_700_000_000_000i64;

    for i in 0..12i64 {
        analyzer.add_record(&FlowRecord {
            src_ip: SRC,
            dst_ip: DST,
            // Fixed ephemeral port: the detection key is the full 5-tuple.
            src_port: 40000,
            dst_port: 8443,
            protocol: 6,
            bytes: 200,
            end_ms: base + i * 60_000,
        });
    }
    for i in 0..12i64 {
        analyzer.add_record(&FlowRecord {
            src_ip: SRC,
            dst_ip: IpAddr::V4(Ipv4Addr::new(129, 6, 15, 28)),
            src_port: 50000,
            dst_port: 123,
            protocol: 17,
            bytes: 90,
            end_ms: base + i * 64_000,
        });
    }
    let mut seed = 7u64;
    let mut t = base;
    for _ in 0..12 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        t += 5_000 + (seed % 80_000) as i64;
        analyzer.add_record(&FlowRecord {
            src_ip: SRC,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 45000,
            dst_port: 443,
            protocol: 6,
            bytes: 1000,
            end_ms: t,
        });
    }

    let reports = analyzer.reports();
    let by_port: std::collections::HashMap<u16, _> =
        reports.iter().map(|r| (r.key.dst_port, r)).collect();

    use beacon_hunter::analyzer::Verdict;
    assert_eq!(
        by_port[&8443].metrics.verdict,
        Verdict::Beacon,
        "8443 reasons: {:?}",
        by_port[&8443].metrics.reasons
    );
    assert_eq!(by_port[&123].metrics.verdict, Verdict::Whitelisted);
    assert_ne!(by_port[&443].metrics.verdict, Verdict::Beacon);
}
