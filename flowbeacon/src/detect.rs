//! 信标检测：按 (源IP, 目的IP, 目的端口) 聚合连接时刻，
//! 对连接间隔做周期性检验，容忍周期漂移与抖动，排除常见正常心跳。

use crate::flow::{FlowRecord, PairKey};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone)]
pub struct DetectorConfig {
    /// 至少多少次连接才参与判定（样本太少时 CV 没有意义）
    pub min_count: usize,
    /// 间隔变异系数（标准差/均值）上限：容忍的抖动比例
    pub max_cv: f64,
    /// 总跨度至少覆盖多少个周期，防止「突发集中」被误判为周期
    pub min_span_factor: f64,
    /// 字节数变异系数上限：信标载荷通常大小相近（0 = 不启用）
    pub max_byte_cv: f64,
    /// 每个键最多保留的时间戳个数（防爆内存，也够覆盖长周期）
    pub max_history: usize,
    /// 正常心跳端口白名单（NTP=123, DNS=53 等），不参与判定
    pub exclude_ports: Vec<u16>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            min_count: 8,
            max_cv: 0.25,
            min_span_factor: 4.0,
            max_byte_cv: 0.5,
            max_history: 1024,
            exclude_ports: vec![53, 123],
        }
    }
}

struct PairSeries {
    /// 连接时刻（unix ms），插入时不保证有序，分析时排序
    times: Vec<i64>,
    bytes: Vec<u64>,
    first_seen: i64,
    last_seen: i64,
}

impl PairSeries {
    fn new(t: i64) -> Self {
        PairSeries {
            times: Vec::with_capacity(32),
            bytes: Vec::with_capacity(32),
            first_seen: t,
            last_seen: t,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BeaconReport {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub count: usize,
    pub period_ms: f64,
    pub jitter_ms: f64,
    pub cv: f64,
    pub byte_cv: f64,
    pub span_ms: i64,
    pub score: f64,
    pub first_seen: i64,
    pub last_seen: i64,
}

pub struct Detector {
    cfg: DetectorConfig,
    series: HashMap<PairKey, PairSeries>,
    pub excluded: u64,
}

impl Detector {
    pub fn new(cfg: DetectorConfig) -> Self {
        Detector {
            cfg,
            series: HashMap::new(),
            excluded: 0,
        }
    }

    fn is_excluded(&mut self, rec: &FlowRecord) -> bool {
        // 正常心跳：NTP / DNS 等（两个方向都排除）
        if self.cfg.exclude_ports.contains(&rec.dst_port)
            || self.cfg.exclude_ports.contains(&rec.src_port)
        {
            return true;
        }
        // 组播 / 广播 / 未指定地址不可能是 C2 回连
        match rec.dst {
            IpAddr::V4(a) => {
                let o = a.octets();
                if o[0] >= 224 || a.is_unspecified() {
                    return true;
                }
            }
            IpAddr::V6(a) => {
                if a.is_multicast() || a.is_unspecified() {
                    return true;
                }
            }
        }
        false
    }

    pub fn ingest(&mut self, rec: &FlowRecord) {
        if self.is_excluded(rec) {
            self.excluded += 1;
            return;
        }
        let key = rec.pair_key();
        let t = rec.start_ms;
        let s = self
            .series
            .entry(key)
            .or_insert_with(|| PairSeries::new(t));
        s.times.push(t);
        s.bytes.push(rec.bytes);
        if t < s.first_seen {
            s.first_seen = t;
        }
        if t > s.last_seen {
            s.last_seen = t;
        }
        // 超长截断：丢最旧的（对周期检测影响最小）
        if s.times.len() > self.cfg.max_history {
            let drop = s.times.len() - self.cfg.max_history;
            s.times.drain(..drop);
            s.bytes.drain(..drop);
        }
    }

    pub fn tracked_pairs(&self) -> usize {
        self.series.len()
    }

    /// 全量分析，返回按分数降序的判定结果
    pub fn analyze(&self) -> Vec<BeaconReport> {
        let mut reports = Vec::new();
        for (key, s) in &self.series {
            if s.times.len() < self.cfg.min_count {
                continue;
            }
            let mut ts = s.times.clone();
            ts.sort_unstable();
            // 相邻去重（同一条流可能被重复导出）
            ts.dedup();
            if ts.len() < self.cfg.min_count {
                continue;
            }
            let intervals: Vec<f64> = ts.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
            let n = intervals.len() as f64;
            let mean = intervals.iter().sum::<f64>() / n;
            if mean <= 0.0 {
                continue;
            }
            let var = intervals
                .iter()
                .map(|x| (x - mean) * (x - mean))
                .sum::<f64>()
                / n;
            let std = var.sqrt();
            let cv = std / mean;

            // 跨度检验：首末差至少要覆盖 min_span_factor 个平均周期
            let span = ts[ts.len() - 1] - ts[0];
            if (span as f64) < mean * self.cfg.min_span_factor {
                continue;
            }

            // 字节数一致性：信标心跳载荷通常差不多大
            let bn = s.bytes.len() as f64;
            let bmean = s.bytes.iter().sum::<u64>() as f64 / bn;
            let byte_cv = if bmean > 0.0 {
                let bv = s
                    .bytes
                    .iter()
                    .map(|&b| (b as f64 - bmean).powi(2))
                    .sum::<f64>()
                    / bn;
                bv.sqrt() / bmean
            } else {
                0.0
            };
            if self.cfg.max_byte_cv > 0.0 && byte_cv > self.cfg.max_byte_cv {
                continue;
            }

            if cv > self.cfg.max_cv {
                continue;
            }

            // 评分：周期性为主，样本量与字节一致性为辅
            let regularity = 1.0 - (cv / self.cfg.max_cv).min(1.0);
            let count_factor = ((ts.len() as f64) / (self.cfg.min_count as f64 * 2.0)).min(1.0);
            let byte_factor = if self.cfg.max_byte_cv > 0.0 {
                1.0 - (byte_cv / self.cfg.max_byte_cv).min(1.0)
            } else {
                0.5
            };
            let score = 0.6 * regularity + 0.25 * count_factor + 0.15 * byte_factor;

            reports.push(BeaconReport {
                src: key.src,
                dst: key.dst,
                dst_port: key.dst_port,
                count: ts.len(),
                period_ms: mean,
                jitter_ms: std,
                cv,
                byte_cv,
                span_ms: span,
                score,
                first_seen: s.first_seen,
                last_seen: s.last_seen,
            });
        }
        reports.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        reports
    }

    /// JSON 导出（手写，避免外部依赖）
    pub fn reports_json(reports: &[BeaconReport]) -> String {
        let mut s = String::from("[\n");
        for (i, r) in reports.iter().enumerate() {
            s.push_str(&format!(
                "  {{\n    \"src\": \"{}\",\n    \"dst\": \"{}\",\n    \"dst_port\": {},\n    \"count\": {},\n    \"period_sec\": {:.3},\n    \"jitter_sec\": {:.3},\n    \"cv\": {:.4},\n    \"byte_cv\": {:.4},\n    \"span_sec\": {:.1},\n    \"score\": {:.3},\n    \"first_seen_ms\": {},\n    \"last_seen_ms\": {}\n  }}{}\n",
                r.src, r.dst, r.dst_port, r.count,
                r.period_ms / 1000.0, r.jitter_ms / 1000.0,
                r.cv, r.byte_cv, r.span_ms as f64 / 1000.0,
                r.score, r.first_seen, r.last_seen,
                if i + 1 < reports.len() { "," } else { "" }
            ));
        }
        s.push_str("]\n");
        s
    }
}
