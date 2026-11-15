//! NetFlow v9 (RFC 3954) / IPFIX (RFC 7011) wire-protocol parser.
//!
//! Design points required by the task:
//! * Templates are keyed by **(exporting device, observation domain)** — two
//!   switches may reuse the same template id with different field layouts.
//! * When a data flowset references a template we have not seen yet, the raw
//!   flowset is buffered and replayed once the template arrives.
//! * No `unsafe`, no external crates.

use std::collections::HashMap;
use std::net::IpAddr;

// ---- Set ids shared by NF9 and IPFIX ------------------------------------
pub(crate) const TEMPLATE_SET: u16 = 2;
pub(crate) const OPTIONS_TEMPLATE_SET: u16 = 3;
const PENDING_PER_DOMAIN: usize = 2048;
const PENDING_TOTAL: usize = 16384;

/// Template cache / pending-buffer key: exporter address + observation domain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DomainKey {
    pub exporter: IpAddr,
    pub domain_id: u32,
}

/// One field specifier inside a template.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FieldSpec {
    /// NF9 field type / IPFIX information element id.
    pub ie: u16,
    /// Length in bytes on the wire (0xffff denotes variable length in IPFIX).
    pub len: u16,
    /// IPFIX enterprise number; 0 for IANA IEs and every NF9 field.
    pub enterprise: u32,
}

#[derive(Clone, Debug)]
pub struct Template {
    pub id: u16,
    pub fields: Vec<FieldSpec>,
    /// Scope field count for options templates (0 = ordinary data template).
    pub scope_count: u16,
}

/// A fully decoded flow record with only the fields beaconing analysis needs.
#[derive(Clone, Debug)]
pub struct FlowRecord {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u64,
    /// Absolute flow end timestamp, milliseconds since Unix epoch.
    pub end_ms: i64,
}

#[derive(Default, Clone, Debug)]
pub struct ParserStats {
    pub packets: u64,
    pub flowsets: u64,
    pub data_flowsets: u64,
    pub records: u64,
    pub records_buffered: u64,
    pub records_replayed: u64,
    pub templates_seen: u64,
    pub pending_overflow: u64,
    /// Records skipped because a mandatory field (5-tuple element) was absent.
    pub records_incomplete: u64,
    pub decode_errors: u64,
}

/// A data flowset held while its template is unknown.
struct Pending {
    key: DomainKey,
    template_id: u16,
    /// Header export time (ms epoch) — used to resolve relative timestamps.
    export_ms: i64,
    /// Header sysUpTime (NF9 only, 0 for IPFIX).
    sysup: u32,
    payload: Vec<u8>,
}

pub struct Parser {
    templates: HashMap<DomainKey, HashMap<u16, Template>>,
    pending: Vec<Pending>,
    pub stats: ParserStats,
    // Per-packet decode context (reset on every `parse` call).
    current_export_ms: i64,
    current_sysup: u32,
    /// Records produced by template-replay during the current parse call.
    replayed: Vec<FlowRecord>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            templates: HashMap::new(),
            pending: Vec::new(),
            stats: ParserStats::default(),
            current_export_ms: 0,
            current_sysup: 0,
            replayed: Vec::new(),
        }
    }

    /// Number of flowsets currently buffered awaiting templates.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Parse one UDP datagram. Returns all flow records that can be decoded
    /// immediately plus any records unlocked by templates arriving in this
    /// same datagram (replay).
    pub fn parse(&mut self, packet: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, String> {
        self.stats.packets += 1;
        self.replayed.clear();
        if packet.len() < 4 {
            self.stats.decode_errors += 1;
            return Err("packet shorter than version field".into());
        }
        let version = u16::from_be_bytes([packet[0], packet[1]]);
        let direct = match version {
            9 => self.parse_nf9(packet, exporter),
            10 => self.parse_ipfix(packet, exporter),
            other => {
                self.stats.decode_errors += 1;
                return Err(format!("unsupported NetFlow/IPFIX version {other}"));
            }
        }?;
        let mut all = direct;
        all.append(&mut self.replayed);
        Ok(all)
    }

    // -- NF9 (RFC 3954) ----------------------------------------------------
    fn parse_nf9(&mut self, p: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, String> {
        if p.len() < 20 {
            self.stats.decode_errors += 1;
            return Err("NF9 header shorter than 20 bytes".into());
        }
        let count = read_u16(p, 2);
        let sysup = read_u32(p, 4);
        let unix_secs = read_u32(p, 8) as i64;
        let source_id = read_u32(p, 16);
        let key = DomainKey {
            exporter,
            domain_id: source_id,
        };
        self.current_export_ms = unix_secs * 1000;
        self.current_sysup = sysup;
        self.walk_sets(p, 20, key, true, count)
    }

    // -- IPFIX (RFC 7011) --------------------------------------------------
    fn parse_ipfix(&mut self, p: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, String> {
        if p.len() < 16 {
            self.stats.decode_errors += 1;
            return Err("IPFIX header shorter than 16 bytes".into());
        }
        let length = read_u16(p, 2) as usize;
        if length > p.len() || length < 16 {
            self.stats.decode_errors += 1;
            return Err(format!("IPFIX length {length} outside datagram"));
        }
        let unix_secs = read_u32(p, 4) as i64;
        let odid = read_u32(p, 12);
        let key = DomainKey {
            exporter,
            domain_id: odid,
        };
        self.current_export_ms = unix_secs * 1000;
        self.current_sysup = 0;
        self.walk_sets(p, 16, key, false, 0)
    }

    /// Common set-walking logic for both protocols.
    fn walk_sets(
        &mut self,
        p: &[u8],
        header_len: usize,
        key: DomainKey,
        is_nf9: bool,
        header_count: u16,
    ) -> Result<Vec<FlowRecord>, String> {
        let mut out = Vec::new();
        let end_limit = if is_nf9 {
            p.len()
        } else {
            read_u16(p, 2) as usize
        };
        let mut off = header_len;
        let _ = header_count; // advisory; set framing is authoritative

        while off + 4 <= end_limit {
            let set_id = read_u16(p, off);
            let set_len = read_u16(p, off + 2) as usize;
            if set_len < 4 || off + set_len > end_limit {
                self.stats.decode_errors += 1;
                return Err(format!(
                    "flowset {set_id} has invalid length {set_len} at offset {off}"
                ));
            }
            self.stats.flowsets += 1;
            let body_end = off + set_len;

            match set_id {
                TEMPLATE_SET => {
                    self.parse_template_set(p, off + 4, body_end, key)?;
                }
                OPTIONS_TEMPLATE_SET => {
                    if is_nf9 {
                        self.parse_nf9_options(p, off + 4, body_end, key)?;
                    } else {
                        self.parse_ipfix_options(p, off + 4, body_end, key)?;
                    }
                }
                _ => {
                    self.stats.data_flowsets += 1;
                    let payload = p[off + 4..body_end].to_vec();
                    self.consume_data_set(set_id, &payload, key, &mut out);
                }
            }
            off = body_end;
        }
        Ok(out)
    }

    // -- template sets -----------------------------------------------------
    fn parse_template_set(
        &mut self,
        p: &[u8],
        start: usize,
        end: usize,
        key: DomainKey,
    ) -> Result<(), String> {
        let mut off = start;
        while off + 4 <= end {
            let tid = read_u16(p, off);
            let field_count = read_u16(p, off + 2) as usize;
            off += 4;
            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let (spec, next) = read_field_spec(p, off)?;
                fields.push(spec);
                off = next;
            }
            if off > end {
                self.stats.decode_errors += 1;
                return Err("template record overruns flowset".into());
            }
            self.install_template(
                key,
                Template {
                    id: tid,
                    fields,
                    scope_count: 0,
                },
            );
            off = skip_padding(p, off, end);
            if off == end || remaining_all_zero(p, off, end) {
                break;
            }
        }
        Ok(())
    }

    fn parse_nf9_options(
        &mut self,
        p: &[u8],
        start: usize,
        end: usize,
        key: DomainKey,
    ) -> Result<(), String> {
        let mut off = start;
        while off + 6 <= end {
            let tid = read_u16(p, off);
            let scope_len = read_u16(p, off + 2) as usize;
            let option_len = read_u16(p, off + 4) as usize;
            off += 6;
            let total = scope_len + option_len;
            if !total.is_multiple_of(4) || off + total > end {
                self.stats.decode_errors += 1;
                return Err("NF9 options template length invalid".into());
            }
            let mut fields = Vec::new();
            let spec_end = off + total;
            while off < spec_end {
                let (spec, next) = read_field_spec(p, off)?;
                fields.push(spec);
                off = next;
            }
            self.install_template(
                key,
                Template {
                    id: tid,
                    fields,
                    scope_count: (scope_len / 4) as u16,
                },
            );
            off = skip_padding(p, off, end);
            if off == end || remaining_all_zero(p, off, end) {
                break;
            }
        }
        Ok(())
    }

    fn parse_ipfix_options(
        &mut self,
        p: &[u8],
        start: usize,
        end: usize,
        key: DomainKey,
    ) -> Result<(), String> {
        let mut off = start;
        while off + 6 <= end {
            let tid = read_u16(p, off);
            let scope_bytes = read_u16(p, off + 2) as usize;
            let option_bytes = read_u16(p, off + 4) as usize;
            off += 6;
            let spec_end = off + scope_bytes + option_bytes;
            if spec_end > end {
                self.stats.decode_errors += 1;
                return Err("IPFIX options template length invalid".into());
            }
            // Template withdrawal (RFC 7011 §3.4.2.2): zero tid, no fields.
            if tid == 0 && scope_bytes + option_bytes == 0 {
                off = skip_padding(p, off, end);
                continue;
            }
            let mut fields = Vec::new();
            let mut scope_count = 0u16;
            let scope_end = off + scope_bytes;
            let mut cur = off;
            while cur < scope_end {
                let (spec, next) = read_field_spec(p, cur)?;
                if next > scope_end {
                    self.stats.decode_errors += 1;
                    return Err("scope field crosses scope region".into());
                }
                fields.push(spec);
                scope_count += 1;
                cur = next;
            }
            while cur < spec_end {
                let (spec, next) = read_field_spec(p, cur)?;
                fields.push(spec);
                cur = next;
            }
            self.install_template(
                key,
                Template {
                    id: tid,
                    fields,
                    scope_count,
                },
            );
            off = skip_padding(p, spec_end, end);
            if off == end || remaining_all_zero(p, off, end) {
                break;
            }
        }
        Ok(())
    }

    fn install_template(&mut self, key: DomainKey, t: Template) {
        self.stats.templates_seen += 1;
        let tid = t.id;
        self.templates.entry(key).or_default().insert(tid, t);
        // Replay buffered data flowsets that now have a template.
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].key == key && self.pending[i].template_id == tid {
                let pend = self.pending.remove(i);
                let tpl = match self.templates.get(&key).and_then(|m| m.get(&tid)).cloned() {
                    Some(x) => x,
                    None => continue,
                };
                // Resolve relative timestamps against the *buffered* packet's
                // export context, not the current one.
                self.current_export_ms = pend.export_ms;
                self.current_sysup = pend.sysup;
                let records = self.decode_payload(&tpl, &pend.payload);
                self.stats.records_replayed += records.len() as u64;
                self.replayed.extend(records);
            } else {
                i += 1;
            }
        }
    }

    fn consume_data_set(
        &mut self,
        set_id: u16,
        payload: &[u8],
        key: DomainKey,
        out: &mut Vec<FlowRecord>,
    ) {
        let tpl = match self
            .templates
            .get(&key)
            .and_then(|m| m.get(&set_id))
            .cloned()
        {
            Some(t) => t,
            None => {
                // Late template: buffer the whole flowset for replay.
                let per_domain = self.pending.iter().filter(|x| x.key == key).count();
                if per_domain >= PENDING_PER_DOMAIN || self.pending.len() >= PENDING_TOTAL {
                    // Drop the oldest globally — a stalled exporter must not
                    // be able to exhaust memory.
                    self.pending.remove(0);
                    self.stats.pending_overflow += 1;
                }
                self.pending.push(Pending {
                    key,
                    template_id: set_id,
                    export_ms: self.current_export_ms,
                    sysup: self.current_sysup,
                    payload: payload.to_vec(),
                });
                self.stats.records_buffered += 1;
                return;
            }
        };
        let records = self.decode_payload(&tpl, payload);
        out.extend(records);
    }

    /// Decode every record inside one data flowset payload.
    fn decode_payload(&mut self, tpl: &Template, payload: &[u8]) -> Vec<FlowRecord> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < payload.len() {
            if remaining_all_zero(payload, off, payload.len()) {
                break; // padding
            }
            let before = off;
            let mut src_ip: Option<IpAddr> = None;
            let mut dst_ip: Option<IpAddr> = None;
            let mut src_port: Option<u16> = None;
            let mut dst_port: Option<u16> = None;
            let mut protocol: Option<u8> = None;
            let mut bytes: Option<u64> = None;
            let mut first_abs_ms: Option<i64> = None;
            let mut last_abs_ms: Option<i64> = None;
            let mut first_rel_ms: Option<i64> = None;
            let mut last_rel_ms: Option<i64> = None;
            let mut ok = true;

            for spec in &tpl.fields {
                let (value, next) = match read_field_value(payload, off, spec.len) {
                    Ok(v) => v,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                };
                off = next;
                // Only IANA IEs (enterprise 0) carry the fields we model.
                if spec.enterprise != 0 {
                    continue;
                }
                match spec.ie {
                    8 => src_ip = bytes_to_ip(&value),    // srcIPv4
                    12 => dst_ip = bytes_to_ip(&value),   // dstIPv4
                    27 => src_ip = bytes_to_ipv6(&value), // srcIPv6
                    28 => dst_ip = bytes_to_ipv6(&value), // dstIPv6
                    7 => src_port = Some(read_be_u16(&value)),
                    11 => dst_port = Some(read_be_u16(&value)),
                    4 => protocol = value.first().copied(),
                    1 | 85 => bytes = Some(read_be_u64(&value)),
                    // Absolute timestamps (IPFIX IEs).
                    150 => first_abs_ms = Some(read_be_u64(&value) as i64 * 1000),
                    151 => last_abs_ms = Some(read_be_u64(&value) as i64 * 1000),
                    152 => first_abs_ms = Some(read_be_u64(&value) as i64),
                    153 => last_abs_ms = Some(read_be_u64(&value) as i64),
                    // Relative sysUpTime timestamps (NF9 IEs, ms).
                    22 => first_rel_ms = Some(read_be_u32(&value) as i64),
                    21 => last_rel_ms = Some(read_be_u32(&value) as i64),
                    _ => {}
                }
            }
            if !ok || off == before {
                self.stats.decode_errors += 1;
                break;
            }

            // Resolve flow end: absolute IE wins; otherwise derive from the
            // packet export time and relative sysUpTime delta.
            let end_ms = last_abs_ms
                .or_else(|| {
                    last_rel_ms.map(|rel| {
                        let age = (self.current_sysup as i64 - rel).max(0);
                        self.current_export_ms - age
                    })
                })
                .or_else(|| {
                    first_abs_ms.or(first_rel_ms.map(|rel| {
                        let age = (self.current_sysup as i64 - rel).max(0);
                        self.current_export_ms - age
                    }))
                })
                .unwrap_or(self.current_export_ms);

            match (src_ip, dst_ip, protocol) {
                (Some(src_ip), Some(dst_ip), Some(protocol)) => {
                    self.stats.records += 1;
                    out.push(FlowRecord {
                        src_ip,
                        dst_ip,
                        src_port: src_port.unwrap_or(0),
                        dst_port: dst_port.unwrap_or(0),
                        protocol,
                        bytes: bytes.unwrap_or(0),
                        end_ms,
                    });
                }
                _ => {
                    self.stats.records_incomplete += 1;
                }
            }
        }
        out
    }
}

// ---- low-level helpers ---------------------------------------------------

fn read_u16(p: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([p[off], p[off + 1]])
}
fn read_u32(p: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]])
}

fn read_be_u16(v: &[u8]) -> u16 {
    let mut b = [0u8; 2];
    let n = v.len().min(2);
    b[2 - n..].copy_from_slice(&v[..n]);
    u16::from_be_bytes(b)
}
fn read_be_u32(v: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    let n = v.len().min(4);
    b[4 - n..].copy_from_slice(&v[..n]);
    u32::from_be_bytes(b)
}
fn read_be_u64(v: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = v.len().min(8);
    b[8 - n..].copy_from_slice(&v[..n]);
    u64::from_be_bytes(b)
}

fn bytes_to_ip(v: &[u8]) -> Option<IpAddr> {
    if v.len() == 4 {
        let b: [u8; 4] = v.try_into().ok()?;
        Some(IpAddr::V4(b.into()))
    } else {
        bytes_to_ipv6(v)
    }
}
fn bytes_to_ipv6(v: &[u8]) -> Option<IpAddr> {
    let b: [u8; 16] = v.try_into().ok()?;
    Some(IpAddr::V6(b.into()))
}

/// Read one 4-byte (NF9) or 4/8-byte (IPFIX enterprise bit) field specifier.
fn read_field_spec(p: &[u8], off: usize) -> Result<(FieldSpec, usize), String> {
    if off + 4 > p.len() {
        return Err("truncated field specifier".into());
    }
    let word = read_u32(p, off);
    let enterprise_bit = (word & 0x8000_0000) != 0;
    let ie = (word >> 16) as u16 & 0x7fff;
    let len = word as u16;
    if enterprise_bit {
        if off + 8 > p.len() {
            return Err("truncated enterprise field specifier".into());
        }
        let enterprise = read_u32(p, off + 4);
        Ok((
            FieldSpec {
                ie,
                len,
                enterprise,
            },
            off + 8,
        ))
    } else {
        Ok((
            FieldSpec {
                ie,
                len,
                enterprise: 0,
            },
            off + 4,
        ))
    }
}

/// Read one field value, honoring IPFIX variable-length encoding (RFC 7012
/// §3.2): a 1-byte length when < 255, or 0xff followed by a 2-byte length.
fn read_field_value(p: &[u8], off: usize, spec_len: u16) -> Result<(Vec<u8>, usize), String> {
    if spec_len != 0xffff {
        let len = spec_len as usize;
        if off + len > p.len() {
            return Err("field overruns flowset".into());
        }
        return Ok((p[off..off + len].to_vec(), off + len));
    }
    if off >= p.len() {
        return Err("missing varlen length byte".into());
    }
    let first = p[off];
    if first != 0xff {
        let len = first as usize;
        let start = off + 1;
        if start + len > p.len() {
            return Err("varlen field overruns flowset".into());
        }
        return Ok((p[start..start + len].to_vec(), start + len));
    }
    if off + 3 > p.len() {
        return Err("truncated long varlen length".into());
    }
    let len = u16::from_be_bytes([p[off + 1], p[off + 2]]) as usize;
    let start = off + 3;
    if start + len > p.len() {
        return Err("long varlen field overruns flowset".into());
    }
    Ok((p[start..start + len].to_vec(), start + len))
}

fn remaining_all_zero(p: &[u8], off: usize, end: usize) -> bool {
    off < end && p[off..end].iter().all(|&b| b == 0)
}

fn skip_padding(p: &[u8], off: usize, end: usize) -> usize {
    let mut o = off;
    while o < end && p[o] == 0 {
        o += 1;
    }
    o
}
