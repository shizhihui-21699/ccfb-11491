//! 模板缓存：按 (导出器源地址, 观察域/Source ID, 模板ID) 分别缓存。
//! 数据先于模板到达时（UDP 乱序 / 模板重传间隔），把原始 Data Set 暂存，
//! 等模板到达后回放解析。

use std::collections::HashMap;
use std::net::IpAddr;

/// NetFlow v9 / IPFIX 共用的字段语义编号（IPFIX IANA 元素号，v9 与之兼容）
#[derive(Debug, Clone, Copy)]
pub struct TemplateField {
    pub element_id: u16,
    pub length: u16, // 0xFFFF = 变长（IPFIX）
}

#[derive(Debug, Clone)]
pub struct Template {
    pub id: u16,
    pub fields: Vec<TemplateField>,
    /// 定长记录的整条长度（变长字段按 0 计，解析时单独处理）
    pub fixed_len: usize,
    pub has_varlen: bool,
}

impl Template {
    pub fn new(id: u16, fields: Vec<TemplateField>) -> Self {
        let mut fixed = 0usize;
        let mut var = false;
        for f in &fields {
            if f.length == 0xFFFF {
                var = true;
            } else {
                fixed += f.length as usize;
            }
        }
        Template {
            id,
            fields,
            fixed_len: fixed,
            has_varlen: var,
        }
    }
}

/// 缓存键：来源地址 + 观察域（v9 的 Source ID / IPFIX 的 Observation Domain ID）+ 模板号
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub exporter: IpAddr,
    pub obs_domain: u32,
    pub template_id: u16,
}

/// 模板未到之前暂存的数据
#[derive(Debug, Clone)]
pub struct PendingSet {
    pub data: Vec<u8>,
    /// v9 需要包头里的 (unix_secs, sys_uptime) 才能还原绝对时间，随包一起存
    pub export_unix_secs: u32,
    pub sys_uptime_ms: u32,
}

pub struct TemplateCache {
    templates: HashMap<CacheKey, Template>,
    pending: HashMap<CacheKey, Vec<PendingSet>>,
    /// 防止模板永远不到导致内存膨胀
    max_pending_per_key: usize,
    pub pending_dropped: u64,
}

impl TemplateCache {
    pub fn new() -> Self {
        TemplateCache {
            templates: HashMap::new(),
            pending: HashMap::new(),
            max_pending_per_key: 64,
            pending_dropped: 0,
        }
    }

    pub fn learn(&mut self, key: CacheKey, tpl: Template) -> Option<Vec<PendingSet>> {
        self.templates.insert(key, tpl);
        self.pending.remove(&key)
    }

    pub fn get(&self, key: &CacheKey) -> Option<&Template> {
        self.templates.get(key)
    }

    pub fn stash(&mut self, key: CacheKey, set: PendingSet) {
        let q = self.pending.entry(key).or_default();
        if q.len() >= self.max_pending_per_key {
            self.pending_dropped += 1;
            return;
        }
        q.push(set);
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.values().map(|v| v.len()).sum()
    }
}
