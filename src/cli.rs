//! Hand-rolled CLI parsing (no clap — keeps the crate dependency-free).

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub export_path: String,
    pub auto_export_secs: u64,
    pub run_duration: Option<Duration>,
    pub whitelist_ports: Vec<u16>,
    pub whitelist_protos: Vec<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: "0.0.0.0:2055".to_string(),
            export_path: "beacons.json".to_string(),
            auto_export_secs: 30,
            run_duration: None,
            // NTP (123) and DNS (53) are the normal heartbeats called out in
            // the task; ICMP (1) is whitelisted wholesale.
            whitelist_ports: vec![53, 123],
            whitelist_protos: vec![1],
        }
    }
}

const HELP: &str = "\
beacon-hunter — NetFlow v9 / IPFIX collector with beacon detection

USAGE:
    beacon-hunter [OPTIONS]

OPTIONS:
    -b, --bind <ADDR>            UDP listen address (default 0.0.0.0:2055)
    -o, --export <PATH>          JSON export path (default beacons.json)
    -a, --auto-export <SECS>     rewrite the JSON file every N seconds;
                                 0 disables periodic export (default 30)
    -d, --duration <DURATION>    stop after e.g. 90s, 10m, 1h (default: run
                                 until q / Ctrl-C)
        --whitelist-ports <L>    comma-separated UDP/TCP ports to never flag
                                 (default 53,123; repeatable)
        --whitelist-protos <L>   comma-separated IP protocol numbers to never
                                 flag (default 1=ICMP; repeatable)
    -h, --help                   show this help
    -V, --version                show version

INTERACTIVE (TTY):
    q + Enter    flush JSON export and exit
    e + Enter    flush JSON export immediately
    Ctrl-C       same as q

DETECTION DEFAULTS (see README for the trade-offs):
    min 6 samples, median interval 5s..2h, robust jitter (MAD) <= 35%,
    composite periodicity score >= 60/100
";

pub fn parse_args(argv: &[String]) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut ports_overridden = false;
    let mut protos_overridden = false;
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        macro_rules! value {
            ($flag:expr) => {{
                i += 1;
                argv.get(i)
                    .ok_or_else(|| format!("option {} requires a value", $flag))?
            }};
        }
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("beacon-hunter {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-b" | "--bind" => cfg.bind = value!(arg).clone(),
            "-o" | "--export" => cfg.export_path = value!(arg).clone(),
            "-a" | "--auto-export" => {
                cfg.auto_export_secs = parse_u64(value!(arg), arg)?;
            }
            "-d" | "--duration" => {
                cfg.run_duration = Some(parse_duration(value!(arg))?);
            }
            "--whitelist-ports" => {
                if !ports_overridden {
                    cfg.whitelist_ports.clear();
                    ports_overridden = true;
                }
                let v = value!(arg);
                for p in v.split(',') {
                    let p = p.trim();
                    if !p.is_empty() {
                        cfg.whitelist_ports.push(parse_u64(p, arg)? as u16);
                    }
                }
            }
            "--whitelist-protos" => {
                if !protos_overridden {
                    cfg.whitelist_protos.clear();
                    protos_overridden = true;
                }
                let v = value!(arg);
                for p in v.split(',') {
                    let p = p.trim();
                    if !p.is_empty() {
                        cfg.whitelist_protos.push(parse_u64(p, arg)? as u8);
                    }
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    // CLI-supplied whitelists replace defaults (the flag is an override).
    Ok(cfg)
}

fn parse_u64(s: &str, flag: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|_| format!("invalid number for {flag}: {s}"))
}

/// Parse `90s`, `10m`, `1h` or a bare number (seconds).
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1u64),
    };
    let n = num
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {s}"))?;
    Ok(Duration::from_secs(n * mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn defaults() {
        let cfg = parse_args(&args("prog")).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:2055");
        assert_eq!(cfg.whitelist_ports, vec![53, 123]);
        assert_eq!(cfg.auto_export_secs, 30);
    }

    #[test]
    fn duration_suffixes() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn overrides() {
        let cfg = parse_args(&args(
            "prog -b 127.0.0.1:9995 -o out.json -a 0 -d 5m --whitelist-ports 53,5353",
        ))
        .unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9995");
        assert_eq!(cfg.export_path, "out.json");
        assert_eq!(cfg.auto_export_secs, 0);
        assert_eq!(cfg.run_duration, Some(Duration::from_secs(300)));
        assert_eq!(cfg.whitelist_ports, vec![53, 5353]);
    }
}
