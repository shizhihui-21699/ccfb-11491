//! 终端实时界面：ANSI 转义手写，每秒整屏重绘

use crate::detect::BeaconReport;
use crate::parse::ParseStats;
use std::io::Write;

pub struct Ui {
    pub enabled: bool,
}

pub struct UiContext<'a> {
    pub templates: usize,
    pub pending_sets: usize,
    pub pending_dropped: u64,
    pub tracked_pairs: usize,
    pub excluded: u64,
    pub stats: &'a ParseStats,
}

fn fmt_dur(ms: f64) -> String {
    let s = ms / 1000.0;
    if s < 90.0 {
        format!("{:.1}s", s)
    } else if s < 5400.0 {
        format!("{:.1}m", s / 60.0)
    } else {
        format!("{:.2}h", s / 3600.0)
    }
}

impl Ui {
    pub fn new(enabled: bool) -> Self {
        Ui { enabled }
    }

    pub fn enter(&self) {
        if self.enabled {
            let mut o = std::io::stdout();
            // 备用屏幕 + 隐藏光标
            write!(o, "\x1b[?1049h\x1b[?25l").ok();
            o.flush().ok();
        }
    }

    pub fn leave(&self) {
        if self.enabled {
            let mut o = std::io::stdout();
            write!(o, "\x1b[?25h\x1b[?1049l").ok();
            o.flush().ok();
        }
    }

    pub fn draw(&self, ctx: &UiContext, reports: &[BeaconReport]) {
        if !self.enabled {
            return;
        }
        let mut out = String::new();
        out.push_str("\x1b[H"); // 光标回左上角
        out.push_str("\x1b[1m flowbeacon — NetFlow v9 / IPFIX 信标检测\x1b[0m\x1b[K\n");
        out.push_str("\x1b[K\n");

        let s = ctx.stats;
        out.push_str(&format!(
            " 报文: {}  坏包: {}  模板: {}  数据Set: {} (暂存 {} / 回放 {} / 丢弃 {})\x1b[K\n",
            s.packets, s.bad_packets, ctx.templates, s.data_sets,
            ctx.pending_sets, s.replayed_sets, ctx.pending_dropped
        ));
        out.push_str(&format!(
            " 流记录: {}  跟踪对: {}  已排除心跳流量: {}\x1b[K\n",
            s.records, ctx.tracked_pairs, ctx.excluded
        ));
        out.push_str("\x1b[K\n");

        if reports.is_empty() {
            out.push_str(" 暂无可疑信标 (样本不足或周期性不达标)\x1b[K\n");
        } else {
            out.push_str(&format!(
                " \x1b[1;31m可疑信标: {}\x1b[0m\x1b[K\n",
                reports.len()
            ));
            out.push_str("\x1b[K\n");
            out.push_str(
                " \x1b[1mSCORE  SOURCE                 DESTINATION           PORT    COUNT  PERIOD    JITTER    CV      SPAN\x1b[0m\x1b[K\n",
            );
            for r in reports.iter().take(20) {
                let color = if r.score >= 0.7 {
                    "\x1b[1;31m"
                } else if r.score >= 0.5 {
                    "\x1b[1;33m"
                } else {
                    "\x1b[0m"
                };
                out.push_str(&format!(
                    " {}{:.3}  {:<22} {:<21} {:<7} {:<6} {:<9} {:<9} {:<7} {}\x1b[0m\x1b[K\n",
                    color,
                    r.score,
                    r.src.to_string(),
                    r.dst.to_string(),
                    r.dst_port,
                    r.count,
                    fmt_dur(r.period_ms),
                    fmt_dur(r.jitter_ms),
                    format!("{:.3}", r.cv),
                    fmt_dur(r.span_ms as f64),
                ));
            }
        }
        out.push_str("\x1b[K\n\x1b[2m Ctrl-C 退出并打印 JSON\x1b[0m\x1b[K\n");
        out.push_str("\x1b[J"); // 清掉残行
        let mut o = std::io::stdout();
        write!(o, "{}", out).ok();
        o.flush().ok();
    }
}
