//! 测试流量生成器：按 NetFlow v9 / IPFIX 报文格式构造 UDP 数据报，
//! 场景里混入噪声流量、正常心跳（NTP/DNS）和若干带抖动的信标。

use std::net::UdpSocket;
use std::time::Duration;

/// 模板字段布局（v9 与 IPFIX 共用一套元素号）
/// src_v4, dst_v4, src_port, dst_port, proto, octets, packets, start_ms, end_ms
const TEMPLATE_FIELDS: [(u16, u16); 9] = [
    (8, 4),
    (12, 4),
    (7, 2),
    (11, 2),
    (4, 1),
    (1, 4),
    (2, 4),
    (152, 8),
    (153, 8),
];
const TEMPLATE_ID: u16 = 256;
const OBS_DOMAIN: u32 = 1;

/// 确定性伪随机（xorshift64*），避免外部依赖
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
}

#[derive(Clone)]
struct Flow {
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    bytes: u32,
    packets: u32,
    start_ms: i64,
    end_ms: i64,
}

pub struct GenConfig {
    pub target: String,
    pub protocol: Protocol,
    pub duration_sec: i64,
    pub beacons: usize,
    pub noise_hosts: usize,
    pub late_template: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Protocol {
    V9,
    Ipfix,
    Both,
}

/// 组装场景流列表：噪声 + 正常心跳 + 带抖动信标
fn build_scenario(cfg: &GenConfig, now_ms: i64) -> Vec<Flow> {
    let mut rng = Rng::new(0xC0FFEE);
    let mut flows = Vec::new();
    let t0 = now_ms - cfg.duration_sec * 1000;

    // 1) 噪声：随机主机随机时间随机对端，无周期
    for h in 0..cfg.noise_hosts {
        let src = [10, 0, (h / 250) as u8, (h % 250 + 2) as u8];
        let n = rng.range(5, 40);
        for _ in 0..n {
            let t = t0 + rng.below(cfg.duration_sec as u64 * 1000) as i64;
            flows.push(Flow {
                src,
                dst: [203, 0, 113, rng.range(1, 200) as u8],
                src_port: rng.range(1024, 65000) as u16,
                dst_port: [80, 443, 8080, 22][rng.below(4) as usize],
                proto: 6,
                bytes: rng.range(40, 9000) as u32,
                packets: rng.range(1, 20) as u32,
                start_ms: t,
                end_ms: t + rng.range(10, 3000) as i64,
            });
        }
    }

    // 2) 正常心跳：NTP(123) 与 DNS(53)，周期很规整——应被排除
    let ntp_period = 64_000i64;
    let mut t = t0;
    while t < now_ms {
        flows.push(Flow {
            src: [10, 0, 0, 100],
            dst: [203, 0, 113, 10],
            src_port: 49152,
            dst_port: 123,
            proto: 17,
            bytes: 90,
            packets: 1,
            start_ms: t,
            end_ms: t + 5,
        });
        t += ntp_period;
    }
    let dns_period = 30_000i64;
    let mut t = t0;
    while t < now_ms {
        flows.push(Flow {
            src: [10, 0, 0, 101],
            dst: [203, 0, 113, 53],
            src_port: 5353,
            dst_port: 53,
            proto: 17,
            bytes: 70,
            packets: 1,
            start_ms: t,
            end_ms: t + 3,
        });
        t += dns_period;
    }

    // 3) 信标：固定周期 + 高斯-ish 抖动（用均匀抖动近似），字节数稳定
    let beacon_ports = [443u16, 8443, 8080, 4443, 53 + 1000];
    for i in 0..cfg.beacons {
        let period_ms = [60_000i64, 120_000, 300_000, 600_000, 45_000][i % 5];
        let jitter_frac = [0.05f64, 0.10, 0.15, 0.08, 0.20][i % 5];
        let src = [10, 1, (i / 250) as u8, (i % 250 + 2) as u8];
        let dst = [198, 51, 100, (10 + i) as u8];
        let dport = beacon_ports[i % beacon_ports.len()];
        let base_bytes = rng.range(150, 400) as u32;
        let mut t = t0 + rng.below(period_ms as u64) as i64;
        while t < now_ms {
            let jitter = (rng.next() as f64 / u64::MAX as f64 - 0.5) * 2.0;
            let dt = (period_ms as f64 * (1.0 + jitter_frac * jitter)) as i64;
            t += dt.max(1000);
            if t >= now_ms {
                break;
            }
            flows.push(Flow {
                src,
                dst,
                src_port: rng.range(49152, 65000) as u16, // 源端口每次变，不影响检测
                dst_port: dport,
                proto: 6,
                bytes: base_bytes + rng.range(0, 20) as u32,
                packets: 2,
                start_ms: t,
                end_ms: t + 50,
            });
        }
    }

    flows.sort_by_key(|f| f.start_ms);
    flows
}

// ---------- 报文编码 ----------

fn encode_record(f: &Flow, out: &mut Vec<u8>) {
    out.extend_from_slice(&f.src);
    out.extend_from_slice(&f.dst);
    out.extend_from_slice(&f.src_port.to_be_bytes());
    out.extend_from_slice(&f.dst_port.to_be_bytes());
    out.push(f.proto);
    out.extend_from_slice(&f.bytes.to_be_bytes());
    out.extend_from_slice(&f.packets.to_be_bytes());
    out.extend_from_slice(&(f.start_ms as u64).to_be_bytes());
    out.extend_from_slice(&(f.end_ms as u64).to_be_bytes());
}

fn v9_template_packet(seq: u32, now_ms: i64) -> Vec<u8> {
    let mut p = Vec::new();
    let boot_epoch_ms = now_ms - 3_600_000; // 假装设备已运行 1 小时
    p.extend_from_slice(&9u16.to_be_bytes()); // version
    p.extend_from_slice(&1u16.to_be_bytes()); // count (flowset 数)
    p.extend_from_slice(&3_600_000u32.to_be_bytes()); // sys_uptime ms
    p.extend_from_slice(&((boot_epoch_ms / 1000 + 3_600_000 / 1000) as u32).to_be_bytes()); // unix_secs
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&OBS_DOMAIN.to_be_bytes()); // source id
    // template flowset
    let body_len = 4 + TEMPLATE_FIELDS.len() * 4;
    p.extend_from_slice(&0u16.to_be_bytes()); // flowset id = 0
    p.extend_from_slice(&(4 + body_len as u16).to_be_bytes());
    p.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    p.extend_from_slice(&(TEMPLATE_FIELDS.len() as u16).to_be_bytes());
    for (id, len) in TEMPLATE_FIELDS {
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&len.to_be_bytes());
    }
    p
}

fn v9_data_packet(seq: u32, flows: &[Flow], now_ms: i64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&3_600_000u32.to_be_bytes());
    p.extend_from_slice(&((now_ms / 1000) as u32).to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&OBS_DOMAIN.to_be_bytes());
    let rec_len = 37usize;
    let body_len = flows.len() * rec_len;
    let pad = (4 - body_len % 4) % 4;
    p.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    p.extend_from_slice(&((4 + body_len + pad) as u16).to_be_bytes());
    let mut body = Vec::with_capacity(body_len + pad);
    for f in flows {
        encode_record(f, &mut body);
    }
    body.extend(std::iter::repeat(0u8).take(pad));
    p.extend_from_slice(&body);
    p
}

fn ipfix_template_packet(seq: u32, now_ms: i64) -> Vec<u8> {
    let mut p = Vec::new();
    let body_len = 4 + TEMPLATE_FIELDS.len() * 4;
    let total = 16 + 4 + body_len;
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&((now_ms / 1000) as u32).to_be_bytes()); // export time
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&OBS_DOMAIN.to_be_bytes()); // observation domain
    p.extend_from_slice(&2u16.to_be_bytes()); // set id = 2 (template)
    p.extend_from_slice(&(4 + body_len as u16).to_be_bytes());
    p.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    p.extend_from_slice(&(TEMPLATE_FIELDS.len() as u16).to_be_bytes());
    for (id, len) in TEMPLATE_FIELDS {
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&len.to_be_bytes());
    }
    p
}

fn ipfix_data_packet(seq: u32, flows: &[Flow], now_ms: i64) -> Vec<u8> {
    let rec_len = 37usize;
    let body_len = flows.len() * rec_len;
    let total = 16 + 4 + body_len;
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&10u16.to_be_bytes());
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&((now_ms / 1000) as u32).to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&OBS_DOMAIN.to_be_bytes());
    p.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    p.extend_from_slice(&(4 + body_len as u16).to_be_bytes());
    for f in flows {
        encode_record(f, &mut p);
    }
    p
}

pub fn run(cfg: GenConfig) -> std::io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let flows = build_scenario(&cfg, now_ms);
    println!(
        "场景: {} 条流 / 模拟时长 {}s / 信标 {} 个 -> {}",
        flows.len(),
        cfg.duration_sec,
        cfg.beacons,
        cfg.target
    );

    let protos: Vec<Protocol> = match cfg.protocol {
        Protocol::Both => vec![Protocol::V9, Protocol::Ipfix],
        p => vec![p],
    };

    let mut seq: u32 = 1;
    for proto in protos {
        let (tpl_pkt, mk_data): (Vec<u8>, fn(u32, &[Flow], i64) -> Vec<u8>) = match proto {
            Protocol::V9 => (v9_template_packet(seq, now_ms), v9_data_packet),
            _ => (ipfix_template_packet(seq, now_ms), ipfix_data_packet),
        };
        let name = if proto == Protocol::V9 { "v9" } else { "ipfix" };

        // 每包最多 20 条记录
        let chunks: Vec<&[Flow]> = flows.chunks(20).collect();
        let mut sent = 0usize;

        if cfg.late_template {
            // 先发一批数据（采集端无模板 -> 应暂存），再发模板触发回放
            let first = mk_data(seq, chunks[0], now_ms);
            sock.send_to(&first, &cfg.target)?;
            sent += 1;
            std::thread::sleep(Duration::from_millis(200));
            sock.send_to(&tpl_pkt, &cfg.target)?;
            println!("[{}] 模板晚到模式: 先数据后模板", name);
        } else {
            sock.send_to(&tpl_pkt, &cfg.target)?;
        }

        for chunk in chunks.iter().skip(if cfg.late_template { 1 } else { 0 }) {
            seq += 1;
            let pkt = mk_data(seq, chunk, now_ms);
            sock.send_to(&pkt, &cfg.target)?;
            sent += 1;
            if sent % 50 == 0 {
                std::thread::sleep(Duration::from_millis(5)); // 防止本机 UDP 缓冲溢出
            }
        }
        println!("[{}] 已发送 {} 个数据包", name, sent);
    }
    Ok(())
}
