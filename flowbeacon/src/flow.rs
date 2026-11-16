//! 归一化后的流记录：五元组 + 字节数 + 时间戳

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PairKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u64,
    pub packets: u64,
    /// 流起始时间，unix 毫秒；导出器没带时间戳时退化为采集端接收时间
    pub start_ms: i64,
    pub end_ms: i64,
}

impl FlowRecord {
    pub fn pair_key(&self) -> PairKey {
        PairKey {
            src: self.src,
            dst: self.dst,
            dst_port: self.dst_port,
        }
    }
}

pub fn ip_to_string(ip: &IpAddr) -> String {
    ip.to_string()
}
