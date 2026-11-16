//! flowbeacon — NetFlow v9 / IPFIX 采集 + 信标检测
//!
//! 用法:
//!   flowbeacon listen [--bind 0.0.0.0:9995] [--export out.json] [--no-ui]
//!                     [--min-count 8] [--max-cv 0.25] [--min-span 4.0]
//!                     [--max-byte-cv 0.5] [--exclude-ports 53,123]
//!   flowbeacon gen    [--target 127.0.0.1:9995] [--protocol v9|ipfix|both]
//!                     [--duration-sec 7200] [--beacons 3] [--noise 20]
//!                     [--late-template]

mod detect;
mod flow;
mod gen;
mod parse;
mod template;
mod ui;

use detect::{Detector, DetectorConfig};
use parse::Parser;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static QUIT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_sig: i32) {
    QUIT.store(true, Ordering::SeqCst);
}

fn install_sigint() {
    // 直接声明 libc 符号，避免外部 crate 依赖
    extern "C" {
        fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    }
    const SIGINT: i32 = 2;
    unsafe {
        signal(SIGINT, on_sigint);
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Args {
    cmd: String,
    opts: std::collections::HashMap<String, String>,
    flags: Vec<String>,
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut opts = std::collections::HashMap::new();
    let mut flags = Vec::new();
    let mut it = it.peekable();
    while let Some(a) = it.next() {
        if a.starts_with("--") {
            let name = a.trim_start_matches('-').to_string();
            match it.peek() {
                Some(v) if !v.starts_with("--") => {
                    opts.insert(name, it.next().unwrap());
                }
                _ => flags.push(name),
            }
        }
    }
    Args { cmd, opts, flags }
}

impl Args {
    fn get(&self, k: &str, default: &str) -> String {
        self.opts.get(k).cloned().unwrap_or_else(|| default.into())
    }
    fn get_f64(&self, k: &str, default: f64) -> f64 {
        self.opts.get(k).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    fn get_usize(&self, k: &str, default: usize) -> usize {
        self.opts.get(k).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

fn usage() {
    println!(
        "flowbeacon — NetFlow v9 / IPFIX 信标检测器\n\n\
         采集:  flowbeacon listen [--bind 0.0.0.0:9995] [--export out.json] [--no-ui]\n\
         \x20               [--min-count 8] [--max-cv 0.25] [--min-span 4.0]\n\
         \x20               [--max-byte-cv 0.5] [--exclude-ports 53,123]\n\n\
         生成:  flowbeacon gen [--target 127.0.0.1:9995] [--protocol v9|ipfix|both]\n\
         \x20            [--duration-sec 7200] [--beacons 3] [--noise 20] [--late-template]\n"
    );
}

fn run_listen(args: &Args) -> std::io::Result<()> {
    let bind = args.get("bind", "0.0.0.0:9995");
    let export_path = args.opts.get("export").cloned();
    let ui_enabled = !args.has("no-ui");

    let mut cfg = DetectorConfig {
        min_count: args.get_usize("min-count", 8),
        max_cv: args.get_f64("max-cv", 0.25),
        min_span_factor: args.get_f64("min-span", 4.0),
        max_byte_cv: args.get_f64("max-byte-cv", 0.5),
        ..Default::default()
    };
    if let Some(ports) = args.opts.get("exclude-ports") {
        cfg.exclude_ports = ports
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
    }

    let sock = UdpSocket::bind(&bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut parser = Parser::new();
    let mut detector = Detector::new(cfg);
    let ui = ui::Ui::new(ui_enabled);
    ui.enter();

    install_sigint();
    let mut buf = [0u8; 65535];
    let mut last_draw = Instant::now() - Duration::from_secs(2);

    loop {
        if QUIT.load(Ordering::SeqCst) {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let recs = parser.parse_datagram(&buf[..n], peer.ip(), now_ms());
                for r in recs {
                    detector.ingest(&r);
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        if last_draw.elapsed() >= Duration::from_secs(1) {
            last_draw = Instant::now();
            let reports = detector.analyze();
            let ctx = ui::UiContext {
                templates: parser.cache.template_count(),
                pending_sets: parser.cache.pending_count(),
                pending_dropped: parser.cache.pending_dropped,
                tracked_pairs: detector.tracked_pairs(),
                excluded: detector.excluded,
                stats: &parser.stats,
            };
            ui.draw(&ctx, &reports);
            if let Some(path) = &export_path {
                let _ = std::fs::write(path, Detector::reports_json(&reports));
            }
        }
    }

    ui.leave();
    // 退出时输出最终 JSON 到 stdout（可重定向）
    let reports = detector.analyze();
    let json = Detector::reports_json(&reports);
    if let Some(path) = &export_path {
        let _ = std::fs::write(path, &json);
        eprintln!("最终结果已写入 {}", path);
    }
    println!("{}", json);
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = parse_args();
    match args.cmd.as_str() {
        "listen" => run_listen(&args),
        "gen" => {
            let protocol = match args.get("protocol", "both").as_str() {
                "v9" => gen::Protocol::V9,
                "ipfix" => gen::Protocol::Ipfix,
                _ => gen::Protocol::Both,
            };
            gen::run(gen::GenConfig {
                target: args.get("target", "127.0.0.1:9995"),
                protocol,
                duration_sec: args.get_f64("duration-sec", 7200.0) as i64,
                beacons: args.get_usize("beacons", 3),
                noise_hosts: args.get_usize("noise", 20),
                late_template: args.has("late-template"),
            })
        }
        _ => {
            usage();
            Ok(())
        }
    }
}
