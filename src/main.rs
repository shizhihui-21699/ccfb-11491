//! beacon-hunter entry point: UDP receive loop -> parser -> analyzer -> UI.

use std::io::stdin;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beacon_hunter::analyzer::Analyzer;
use beacon_hunter::cli::{parse_args, Config};
use beacon_hunter::export::{render_json, write_json};
use beacon_hunter::protocol::Parser;
use beacon_hunter::ui::Ui;

enum Command {
    Quit,
    Export,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let cfg = match parse_args(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("argument error: {e}");
            std::process::exit(2);
        }
    };

    let socket = match UdpSocket::bind(&cfg.bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to bind udp://{}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(200))) {
        eprintln!("warning: could not set socket read timeout: {e}");
    }

    let commands = spawn_stdin_thread();
    let mut parser = Parser::new();
    let mut analyzer = Analyzer::new(cfg.whitelist_ports.clone(), cfg.whitelist_protos.clone());
    let tty = is_tty();
    let mut ui = Ui::new(tty);

    let started = Instant::now();
    let mut last_tick = Instant::now();
    let mut last_export = Instant::now();
    let mut buf = [0u8; 65535];
    let mut notice: Option<String> = None;
    let mut quitting = false;

    eprintln!(
        "beacon-hunter listening on udp://{} (whitelist ports {:?}, protos {:?})",
        cfg.bind, cfg.whitelist_ports, cfg.whitelist_protos
    );

    while !quitting {
        // ---- 1. drain whatever datagrams are ready ---------------------
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, addr)) => match parser.parse(&buf[..len], addr.ip()) {
                    Ok(records) => {
                        for rec in &records {
                            analyzer.add_record(rec);
                        }
                    }
                    Err(e) => {
                        eprintln!("decode error from {addr}: {e}");
                    }
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    eprintln!("socket error: {e}");
                    break;
                }
            }
        }

        // ---- 2. handle interactive commands ----------------------------
        match commands.try_recv() {
            Ok(Command::Quit) => quitting = true,
            Ok(Command::Export) => {
                if let Err(e) = do_export(&cfg, &parser, &analyzer, started) {
                    notice = Some(format!("export failed: {e}"));
                } else {
                    notice = Some(format!("exported -> {}", cfg.export_path));
                    last_export = Instant::now();
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {}
        }

        // ---- 3. once per second: refresh UI + periodic export ----------
        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
            let reports = analyzer.reports();
            let auto = if cfg.auto_export_secs > 0 {
                Some(cfg.export_path.as_str())
            } else {
                None
            };
            ui.draw(
                &mut std::io::stdout(),
                &reports,
                &parser.stats,
                parser.pending_count(),
                &cfg.bind,
                started.elapsed().as_millis() as u64,
                auto,
                notice.as_deref(),
            );
            notice = None;

            if cfg.auto_export_secs > 0
                && last_export.elapsed() >= Duration::from_secs(cfg.auto_export_secs)
            {
                if let Err(e) = do_export(&cfg, &parser, &analyzer, started) {
                    eprintln!("auto-export failed: {e}");
                } else {
                    last_export = Instant::now();
                }
            }
        }

        // ---- 4. optional fixed run duration ----------------------------
        if let Some(max) = cfg.run_duration {
            if started.elapsed() >= max {
                quitting = true;
            }
        }
    }

    // Final flush on every exit path (q / duration). Ctrl-C cannot be caught
    // in std-only Rust; the periodic auto-export bounds how much is lost.
    if let Err(e) = do_export(&cfg, &parser, &analyzer, started) {
        eprintln!("final export failed: {e}");
        std::process::exit(1);
    }
    eprintln!("final report written to {}", cfg.export_path);
}

fn do_export(
    cfg: &Config,
    parser: &Parser,
    analyzer: &Analyzer,
    started: Instant,
) -> std::io::Result<()> {
    let reports = analyzer.reports();
    let json = render_json(
        &reports,
        &parser.stats,
        parser.pending_count(),
        now_ms(),
        started.elapsed().as_millis() as u64,
    );
    let path = PathBuf::from(&cfg.export_path);
    write_json(&path, &json)
}

/// `q`/`e` + Enter on stdin. Blocking read lives on its own thread so the
/// receive loop never stalls; when stdin closes (e.g. container without a
/// TTY) the thread simply exits.
fn spawn_stdin_thread() -> Receiver<Command> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match stdin().read_line(&mut line) {
                Ok(0) => return, // EOF
                Ok(_) => {
                    let cmd = line.trim().to_ascii_lowercase();
                    let msg = match cmd.as_str() {
                        "q" | "quit" | "exit" => Some(Command::Quit),
                        "e" | "export" => Some(Command::Export),
                        _ => None,
                    };
                    if let Some(m) = msg {
                        if tx.send(m).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => return,
            }
        }
    });
    rx
}

fn is_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdout())
}
