//! NetFlow v9 (RFC 3954) 与 IPFIX (RFC 7011) 报文解析。
//! 两种协议都是「模板 + 数据」模型，解析器只负责把 Data Set 按模板还原成 FlowRecord。

use crate::flow::FlowRecord;
use crate::template::{CacheKey, PendingSet, Template, TemplateCache, TemplateField};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---- 元素编号（IPFIX IANA，v9 字段类型号与之相同）----
const EL_OCTET_DELTA: u16 = 1;
const EL_PACKET_DELTA: u16 = 2;
const EL_PROTOCOL: u16 = 4;
const EL_SRC_PORT: u16 = 7;
const EL_SRC_IPV4: u16 = 8;
const EL_DST_PORT: u16 = 11;
const EL_DST_IPV4: u16 = 12;
const EL_FIRST_SWITCHED: u16 = 22; // v9: 相对系统启动的毫秒
const EL_LAST_SWITCHED: u16 = 23;
const EL_SRC_IPV6: u16 = 27;
const EL_DST_IPV6: u16 = 28;
const EL_FLOW_START_SEC: u16 = 150;
const EL_FLOW_END_SEC: u16 = 151;
const EL_FLOW_START_MS: u16 = 152;
const EL_FLOW_END_MS: u16 = 153;

#[derive(Default)]
pub struct ParseStats {
    pub packets: u64,
    pub bad_packets: u64,
    pub templates_learned: u64,
    pub data_sets: u64,
    pub buffered_sets: u64,
    pub replayed_sets: u64,
    pub records: u64,
}

pub struct Parser {
    pub cache: TemplateCache,
    pub stats: ParseStats,
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 大端无符号整数，1..=8 字节
fn read_uint(b: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &x in b {
        v = (v << 8) | x as u64;
    }
    v
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            cache: TemplateCache::new(),
            stats: ParseStats::default(),
        }
    }

    /// 解析一个 UDP 数据报，返回还原出的流记录
    pub fn parse_datagram(&mut self, buf: &[u8], exporter: IpAddr, now_ms: i64) -> Vec<FlowRecord> {
        self.stats.packets += 1;
        if buf.len() < 2 {
            self.stats.bad_packets += 1;
            return Vec::new();
        }
        let version = be_u16(buf);
        match version {
            9 => self.parse_v9(buf, exporter, now_ms),
            10 => self.parse_ipfix(buf, exporter, now_ms),
            _ => {
                self.stats.bad_packets += 1;
                Vec::new()
            }
        }
    }

    // ---------------- NetFlow v9 ----------------

    fn parse_v9(&mut self, buf: &[u8], exporter: IpAddr, now_ms: i64) -> Vec<FlowRecord> {
        if buf.len() < 20 {
            self.stats.bad_packets += 1;
            return Vec::new();
        }
        let sys_uptime_ms = be_u32(&buf[4..8]);
        let unix_secs = be_u32(&buf[8..12]);
        let source_id = be_u32(&buf[16..20]);

        let mut out = Vec::new();
        let mut off = 20usize;
        while off + 4 <= buf.len() {
            let set_id = be_u16(&buf[off..]);
            let set_len = be_u16(&buf[off + 2..]) as usize;
            if set_len < 4 || off + set_len > buf.len() {
                break;
            }
            let body = &buf[off + 4..off + set_len];
            match set_id {
                0 => self.learn_v9_templates(body, exporter, source_id, &mut out, now_ms),
                1 => { /* Options Template：本工具用不到，跳过 */ }
                id if id >= 256 => {
                    let key = CacheKey {
                        exporter,
                        obs_domain: source_id,
                        template_id: id,
                    };
                    self.handle_data_set(key, body, unix_secs, sys_uptime_ms, now_ms, &mut out);
                }
                _ => {}
            }
            off += set_len;
        }
        out
    }

    fn learn_v9_templates(
        &mut self,
        mut body: &[u8],
        exporter: IpAddr,
        source_id: u32,
        out: &mut Vec<FlowRecord>,
        now_ms: i64,
    ) {
        while body.len() >= 4 {
            let tid = be_u16(&body[0..]);
            let nfields = be_u16(&body[2..]) as usize;
            body = &body[4..];
            if body.len() < nfields * 4 {
                return;
            }
            let mut fields = Vec::with_capacity(nfields);
            for i in 0..nfields {
                fields.push(TemplateField {
                    element_id: be_u16(&body[i * 4..]),
                    length: be_u16(&body[i * 4 + 2..]),
                });
            }
            body = &body[nfields * 4..];
            self.register_template(exporter, source_id, tid, fields, out, now_ms);
            // 模板 FlowSet 内可能有 4 字节对齐填充
            if body.len() < 4 {
                return;
            }
        }
    }

    // ---------------- IPFIX ----------------

    fn parse_ipfix(&mut self, buf: &[u8], exporter: IpAddr, now_ms: i64) -> Vec<FlowRecord> {
        if buf.len() < 16 {
            self.stats.bad_packets += 1;
            return Vec::new();
        }
        let total_len = be_u16(&buf[2..4]) as usize;
        let export_secs = be_u32(&buf[4..8]);
        let domain_id = be_u32(&buf[12..16]);
        let end = total_len.min(buf.len());

        let mut out = Vec::new();
        let mut off = 16usize;
        while off + 4 <= end {
            let set_id = be_u16(&buf[off..]);
            let set_len = be_u16(&buf[off + 2..]) as usize;
            if set_len < 4 || off + set_len > end {
                break;
            }
            let body = &buf[off + 4..off + set_len];
            match set_id {
                2 => self.learn_ipfix_templates(body, exporter, domain_id, &mut out, now_ms),
                3 => { /* Options Template Set，跳过 */ }
                id if id >= 256 => {
                    let key = CacheKey {
                        exporter,
                        obs_domain: domain_id,
                        template_id: id,
                    };
                    // IPFIX 绝对时间戳字段自带 epoch，export_secs 仅作兜底
                    self.handle_data_set(key, body, export_secs, 0, now_ms, &mut out);
                }
                _ => {}
            }
            off += set_len;
        }
        out
    }

    fn learn_ipfix_templates(
        &mut self,
        mut body: &[u8],
        exporter: IpAddr,
        domain_id: u32,
        out: &mut Vec<FlowRecord>,
        now_ms: i64,
    ) {
        while body.len() >= 4 {
            let tid = be_u16(&body[0..]);
            let nfields = be_u16(&body[2..]) as usize;
            body = &body[4..];
            let mut fields = Vec::with_capacity(nfields);
            let mut ok = true;
            for _ in 0..nfields {
                if body.len() < 4 {
                    ok = false;
                    break;
                }
                let raw_id = be_u16(&body[0..]);
                let len = be_u16(&body[2..]);
                body = &body[4..];
                if raw_id & 0x8000 != 0 {
                    // 企业特定字段：多 4 字节企业号，语义未知，按长度跳过
                    if body.len() < 4 {
                        ok = false;
                        break;
                    }
                    body = &body[4..];
                    fields.push(TemplateField {
                        element_id: 0, // 0 = 未知，解析时仅按长度跳过
                        length: len,
                    });
                } else {
                    fields.push(TemplateField {
                        element_id: raw_id,
                        length: len,
                    });
                }
            }
            if !ok {
                return;
            }
            self.register_template(exporter, domain_id, tid, fields, out, now_ms);
            if body.len() < 4 {
                return;
            }
        }
    }

    // ---------------- 模板注册 / 数据回放 ----------------

    fn register_template(
        &mut self,
        exporter: IpAddr,
        domain: u32,
        tid: u16,
        fields: Vec<TemplateField>,
        out: &mut Vec<FlowRecord>,
        now_ms: i64,
    ) {
        let key = CacheKey {
            exporter,
            obs_domain: domain,
            template_id: tid,
        };
        let tpl = Template::new(tid, fields);
        self.stats.templates_learned += 1;
        if let Some(pending) = self.cache.learn(key, tpl) {
            // 模板晚到：回放之前暂存的数据
            for p in pending {
                self.stats.replayed_sets += 1;
                self.parse_data_with_template(
                    &key,
                    &p.data,
                    p.export_unix_secs,
                    p.sys_uptime_ms,
                    now_ms,
                    out,
                );
            }
        }
    }

    fn handle_data_set(
        &mut self,
        key: CacheKey,
        body: &[u8],
        export_unix_secs: u32,
        sys_uptime_ms: u32,
        now_ms: i64,
        out: &mut Vec<FlowRecord>,
    ) {
        self.stats.data_sets += 1;
        if self.cache.get(&key).is_none() {
            // 模板还没到，先存下来
            self.stats.buffered_sets += 1;
            self.cache.stash(
                key,
                PendingSet {
                    data: body.to_vec(),
                    export_unix_secs,
                    sys_uptime_ms,
                },
            );
            return;
        }
        self.parse_data_with_template(&key, body, export_unix_secs, sys_uptime_ms, now_ms, out);
    }

    fn parse_data_with_template(
        &mut self,
        key: &CacheKey,
        body: &[u8],
        export_unix_secs: u32,
        sys_uptime_ms: u32,
        now_ms: i64,
        out: &mut Vec<FlowRecord>,
    ) {
        let tpl = match self.cache.get(key) {
            Some(t) => t.clone(),
            None => return,
        };
        // v9 的 22/23 字段是「系统启动以来的毫秒」，需要包头换算到 epoch
        let boot_epoch_ms = export_unix_secs as i64 * 1000 - sys_uptime_ms as i64;

        let mut pos = 0usize;
        while pos < body.len() {
            let remaining = &body[pos..];
            if tpl.has_varlen {
                match self.parse_one_varlen(&tpl, remaining, boot_epoch_ms, now_ms) {
                    Some((rec, consumed)) => {
                        out.push(rec);
                        self.stats.records += 1;
                        pos += consumed;
                    }
                    None => break,
                }
            } else {
                if remaining.len() < tpl.fixed_len {
                    break; // 尾部对齐填充
                }
                let (rec, consumed) =
                    parse_one_fixed(&tpl, &remaining[..tpl.fixed_len], boot_epoch_ms, now_ms);
                out.push(rec);
                self.stats.records += 1;
                pos += consumed;
            }
        }
    }

    fn parse_one_varlen(
        &self,
        tpl: &Template,
        buf: &[u8],
        boot_epoch_ms: i64,
        now_ms: i64,
    ) -> Option<(FlowRecord, usize)> {
        let mut b = RecordBuilder::new(boot_epoch_ms, now_ms);
        let mut pos = 0usize;
        for f in &tpl.fields {
            let flen = if f.length == 0xFFFF {
                // IPFIX 变长：1 字节长度，255 则后跟 2 字节长度
                if buf.len() < pos + 1 {
                    return None;
                }
                let l0 = buf[pos] as usize;
                pos += 1;
                if l0 < 255 {
                    l0
                } else {
                    if buf.len() < pos + 2 {
                        return None;
                    }
                    let l = be_u16(&buf[pos..]) as usize;
                    pos += 2;
                    l
                }
            } else {
                f.length as usize
            };
            if buf.len() < pos + flen {
                return None;
            }
            b.feed(f.element_id, &buf[pos..pos + flen]);
            pos += flen;
        }
        Some((b.finish(), pos))
    }
}

fn parse_one_fixed(
    tpl: &Template,
    buf: &[u8],
    boot_epoch_ms: i64,
    now_ms: i64,
) -> (FlowRecord, usize) {
    let mut b = RecordBuilder::new(boot_epoch_ms, now_ms);
    let mut pos = 0usize;
    for f in &tpl.fields {
        let flen = f.length as usize;
        if pos + flen <= buf.len() {
            b.feed(f.element_id, &buf[pos..pos + flen]);
        }
        pos += flen;
    }
    (b.finish(), tpl.fixed_len)
}

struct RecordBuilder {
    rec: FlowRecord,
    first_switched: Option<u64>,
    last_switched: Option<u64>,
    boot_epoch_ms: i64,
    now_ms: i64,
}

impl RecordBuilder {
    fn new(boot_epoch_ms: i64, now_ms: i64) -> Self {
        RecordBuilder {
            rec: FlowRecord {
                src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                src_port: 0,
                dst_port: 0,
                protocol: 0,
                bytes: 0,
                packets: 0,
                start_ms: 0,
                end_ms: 0,
            },
            first_switched: None,
            last_switched: None,
            boot_epoch_ms,
            now_ms,
        }
    }

    fn feed(&mut self, id: u16, raw: &[u8]) {
        match id {
            EL_SRC_IPV4 if raw.len() == 4 => {
                self.rec.src = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
            }
            EL_DST_IPV4 if raw.len() == 4 => {
                self.rec.dst = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
            }
            EL_SRC_IPV6 if raw.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(raw);
                self.rec.src = IpAddr::V6(Ipv6Addr::from(a));
            }
            EL_DST_IPV6 if raw.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(raw);
                self.rec.dst = IpAddr::V6(Ipv6Addr::from(a));
            }
            EL_SRC_PORT => self.rec.src_port = read_uint(raw) as u16,
            EL_DST_PORT => self.rec.dst_port = read_uint(raw) as u16,
            EL_PROTOCOL => self.rec.protocol = read_uint(raw) as u8,
            EL_OCTET_DELTA => self.rec.bytes = read_uint(raw),
            EL_PACKET_DELTA => self.rec.packets = read_uint(raw),
            EL_FIRST_SWITCHED => self.first_switched = Some(read_uint(raw)),
            EL_LAST_SWITCHED => self.last_switched = Some(read_uint(raw)),
            EL_FLOW_START_SEC => self.rec.start_ms = read_uint(raw) as i64 * 1000,
            EL_FLOW_END_SEC => self.rec.end_ms = read_uint(raw) as i64 * 1000,
            EL_FLOW_START_MS => self.rec.start_ms = read_uint(raw) as i64,
            EL_FLOW_END_MS => self.rec.end_ms = read_uint(raw) as i64,
            _ => {}
        }
    }

    fn finish(mut self) -> FlowRecord {
        // v9 相对时间戳换算
        if let Some(fs) = self.first_switched {
            self.rec.start_ms = self.boot_epoch_ms + fs as i64;
        }
        if let Some(ls) = self.last_switched {
            self.rec.end_ms = self.boot_epoch_ms + ls as i64;
        }
        // 导出器没带任何时间戳：用采集端接收时间兜底
        if self.rec.start_ms == 0 {
            self.rec.start_ms = self.now_ms;
        }
        if self.rec.end_ms == 0 {
            self.rec.end_ms = self.rec.start_ms;
        }
        self.rec
    }
}
