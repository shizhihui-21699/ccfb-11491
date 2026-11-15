#!/usr/bin/env python3
"""Generate NetFlow v9 + IPFIX test traffic with embedded beacons.

The emitter talks the wire formats from RFC 3954 (NetFlow v9) and RFC 7011
(IPFIX) directly -- no third-party modules, stdlib only. Run with -I:

    python3 -I tools/gen_flows.py --target 127.0.0.1:2055

Embedded scenario (virtual timeline, ~26 minutes of traffic):

  BEACON A (NF9)   10.10.0.5  -> 198.51.100.20:8443/TCP  period 60s  jitter +-8s
  BEACON B (IPFIX) 10.10.0.6  -> 203.0.113.77:443/TCP     period 120s jitter +-30s + 1 missed tick
  BEACON C (IPFIX) 10.10.0.7  -> 192.0.2.50:9999/UDP      period 45s  jitter +-5s
  BEACON D (IPFIX, late template id 258)
                   10.10.0.8  -> 198.51.100.40:8080/TCP   period 90s  jitter +-6s
  NTP heartbeat    several hosts -> 129.6.15.28:123/UDP   period 64s  (whitelisted)
  DNS chatter      hosts -> 10.10.0.53:53/UDP+TCP         random gaps (whitelisted)
  ICMP pings       10.10.0.30 -> 198.51.100.10 proto 1    period 10s  (whitelisted proto)
  random chatter   10.10.0.20 -> 93.184.216.34:443/TCP    LCG gaps 5..90s (aperiodic)

Both exporters reuse template id 256 with *different field layouts*, which
proves the collector caches templates per (exporter, observation domain)
rather than globally. In --late-templates mode (default) the NF9 template is
withheld until virtual t=150s and IPFIX template 258 until t=200s, so data
flowsets hit the collector before their templates and must be replayed.
"""

import argparse
import socket
import struct
import sys
import time

# -- NF9 field types (RFC 3954) / IPFIX IE ids (RFC 7012, shared numbers) --
IN_BYTES = 1
IN_PKTS = 2
PROTOCOL = 4
L4_SRC_PORT = 7
IPV4_SRC_ADDR = 8
L4_DST_PORT = 11
IPV4_DST_ADDR = 12
LAST_SWITCHED = 21
FIRST_SWITCHED = 22
OCTET_DELTA_COUNT = 85
FLOW_START_MILLISECONDS = 152
FLOW_END_MILLISECONDS = 153

TCP = 6
UDP = 17
ICMP = 1

NF9_EXPORTER = "10.0.0.1"
NF9_DOMAIN = 100
IPFIX_EXPORTER = "10.0.0.2"
IPFIX_DOMAIN = 200
NF9_TEMPLATE_GATE_MS = 150_000
IPFIX_258_GATE_MS = 200_000


class Lcg:
    """Deterministic RNG so runs are reproducible."""

    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next_u64(self):
        self.state = (
            self.state * 6364136223846793005 + 1442695040888963407
        ) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def uniform(self, lo, hi):
        """Uniform float in [lo, hi]."""
        return lo + (self.next_u64() / 0xFFFFFFFFFFFFFFFF) * (hi - lo)

    def jitter_ms(self, amount_ms):
        return int(self.uniform(-amount_ms, amount_ms))


def ip4(text):
    return socket.inet_aton(text)


def pad4(data):
    r = len(data) % 4
    return data + (b"\x00" * ((4 - r) % 4))


def set_header(set_id, payload_len):
    # Set length includes the 4-byte header; payload must already be padded
    # to a 4-byte boundary by the caller.
    return struct.pack("!HH", set_id, payload_len + 4)


# -- template builders ------------------------------------------------------

def nf9_template_256():
    # 25-byte records, NF9 classic relative sysUpTime timestamps.
    fields = [
        (IPV4_SRC_ADDR, 4),
        (IPV4_DST_ADDR, 4),
        (L4_SRC_PORT, 2),
        (L4_DST_PORT, 2),
        (PROTOCOL, 1),
        (IN_BYTES, 4),
        (FIRST_SWITCHED, 4),
        (LAST_SWITCHED, 4),
    ]
    body = struct.pack("!HH", 256, len(fields))
    for ie, length in fields:
        body += struct.pack("!HH", ie, length)
    return set_header(2, len(pad4(body))) + pad4(body)


def ipfix_template_256():
    # Deliberately different order, 8-byte octet counter, absolute ms
    # timestamps, plus an enterprise-specific field to exercise the E-bit.
    plain = [
        (IPV4_DST_ADDR, 4, 0),
        (IPV4_SRC_ADDR, 4, 0),
        (L4_DST_PORT, 2, 0),
        (L4_SRC_PORT, 2, 0),
        (PROTOCOL, 1, 0),
        (OCTET_DELTA_COUNT, 8, 0),
        (FLOW_END_MILLISECONDS, 8, 0),
        (FLOW_START_MILLISECONDS, 8, 0),
    ]
    body = struct.pack("!HH", 256, len(plain) + 1)
    for ie, length, _pen in plain:
        body += struct.pack("!HH", ie, length)
    # Enterprise field: E-bit set, PEN 12345 follows.
    body += struct.pack("!HHI", 0x8000 | 999, 4, 12345)
    return set_header(2, len(pad4(body))) + pad4(body)


def ipfix_template_258():
    fields = [
        (IPV4_SRC_ADDR, 4),
        (IPV4_DST_ADDR, 4),
        (L4_SRC_PORT, 2),
        (L4_DST_PORT, 2),
        (PROTOCOL, 1),
        (IN_BYTES, 4),
        (FLOW_END_MILLISECONDS, 8),
    ]
    body = struct.pack("!HH", 258, len(fields))
    for ie, length in fields:
        body += struct.pack("!HH", ie, length)
    return set_header(2, len(pad4(body))) + pad4(body)


# -- record builders --------------------------------------------------------

def nf9_record(ev, base_ms):
    # Relative sysUpTime timestamps (ms since exporter boot); the packet
    # header carries the matching sysUpTime so the collector can reconstruct
    # the absolute end time.
    age_ms = 500
    sysup = ev["t"]
    return (
        ip4(ev["src"])
        + ip4(ev["dst"])
        + struct.pack("!HHB", ev["sport"], ev["dport"], ev["proto"])
        + struct.pack("!I", ev["bytes"])
        + struct.pack(
            "!II",
            max(0, sysup - age_ms),
            max(0, sysup - age_ms // 2),
        )
    )


def ipfix_256_record(ev, base_ms):
    end_ms = base_ms + ev["t"]
    start_ms = end_ms - 500
    return (
        ip4(ev["dst"])
        + ip4(ev["src"])
        + struct.pack("!HHB", ev["dport"], ev["sport"], ev["proto"])
        + struct.pack("!Q", ev["bytes"])
        + struct.pack("!QQ", end_ms, start_ms)
        + struct.pack("!I", 0xDEADBEEF)  # enterprise-specific field
    )


def ipfix_258_record(ev, base_ms):
    end_ms = base_ms + ev["t"]
    return (
        ip4(ev["src"])
        + ip4(ev["dst"])
        + struct.pack("!HHB", ev["sport"], ev["dport"], ev["proto"])
        + struct.pack("!I", ev["bytes"] & 0xFFFFFFFF)
        + struct.pack("!Q", end_ms)
    )


# -- scenario generation ----------------------------------------------------

def schedule_beacon(rng, src, dst, dport, proto, period_ms, jitter_ms,
                    count, start_ms, missed_ticks=(), sport=40000):
    events = []
    t = start_ms
    for i in range(count):
        if i not in missed_ticks:
            events.append({
                "t": t,
                "src": src,
                "dst": dst,
                # Fixed client port: beaconing malware reuses one socket /
                # small pool, and the analyzer keys on the full 5-tuple.
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "bytes": int(rng.uniform(120, 900)),
            })
        t += period_ms + rng.jitter_ms(jitter_ms)
        t = max(t, start_ms + i * period_ms // 2)  # keep gaps positive
    return events


def schedule_periodic(rng, src, dst, dport, proto, period_ms, jitter_ms,
                      horizon_ms, start_ms=0, sport=50000):
    events = []
    t = start_ms
    i = 0
    while t < horizon_ms:
        events.append({
            "t": t,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "bytes": int(rng.uniform(76, 200)),
        })
        t += period_ms + rng.jitter_ms(jitter_ms)
        i += 1
    return events


def schedule_random(rng, src, dst, dport, proto, count, start_ms=0):
    events = []
    t = start_ms
    for i in range(count):
        events.append({
            "t": t,
            "src": src,
            "dst": dst,
            "sport": 45000 + (i % 1000),
            "dport": dport,
            "proto": proto,
            "bytes": int(rng.uniform(200, 5000)),
        })
        t += int(rng.uniform(5_000, 90_000))
    return events


def build_events(seed):
    rng = Lcg(seed)
    horizon = 26 * 60 * 1000
    nf9, ipfix256, ipfix258 = [], [], []

    # --- NF9 exporter -----------------------------------------------------
    nf9 += schedule_beacon(rng, "10.10.0.5", "198.51.100.20", 8443, TCP,
                           60_000, 8_000, 26, 0)
    for idx, host in enumerate(("10.10.0.11", "10.10.0.12", "10.10.0.13")):
        nf9 += schedule_periodic(rng, host, "129.6.15.28", 123, UDP,
                                 64_000, 2_000, horizon, idx * 20_000)
    nf9 += schedule_random(rng, "10.10.0.21", "10.10.0.53", 53, UDP, 60)
    nf9 += schedule_random(rng, "10.10.0.20", "93.184.216.34", 443, TCP, 40)

    # --- IPFIX exporter, template 256 ------------------------------------
    ipfix256 += schedule_beacon(rng, "10.10.0.6", "203.0.113.77", 443, TCP,
                                120_000, 30_000, 14, 0, missed_ticks=(7,))
    ipfix256 += schedule_beacon(rng, "10.10.0.7", "192.0.2.50", 9999, UDP,
                                45_000, 5_000, 30, 0)
    ipfix256 += schedule_random(rng, "10.10.0.22", "10.10.0.53", 53, TCP, 50)
    ipfix256 += schedule_periodic(rng, "10.10.0.30", "198.51.100.10", 0,
                                  ICMP, 10_000, 400, horizon)

    # --- IPFIX exporter, late template 258 -------------------------------
    ipfix258 += schedule_beacon(rng, "10.10.0.8", "198.51.100.40", 8080, TCP,
                                90_000, 6_000, 18, 0)

    for evs in (nf9, ipfix256, ipfix258):
        evs.sort(key=lambda e: e["t"])
    return nf9, ipfix256, ipfix258


# -- packet assembly -------------------------------------------------------

def nf9_packet(flowsets, seq, base_ms, sysup_ms=0):
    # Header count is advisory (template records make it ambiguous); set it
    # to the data record count of this packet, 0 for template-only packets.
    count = sum(fs[1] for fs in flowsets)
    body = b"".join(fs[0] for fs in flowsets)
    # RFC 3954: export time is wall clock at sysUpTime `sysup_ms`, so with
    # base_ms as the exporter's boot instant they advance together. The
    # header only has second precision, as on real devices.
    export_secs = (base_ms + sysup_ms) // 1000
    header = struct.pack(
        "!HHIIII",
        9,
        count,
        sysup_ms,
        export_secs,
        seq,
        NF9_DOMAIN,
    )
    return header + body


def ipfix_packet(flowsets, seq, base_ms):
    body = b"".join(fs[0] for fs in flowsets)
    length = 16 + len(body)
    header = struct.pack(
        "!HHIII", 10, length, base_ms // 1000, seq, IPFIX_DOMAIN
    )
    return header + body


def data_flowset(template_id, records):
    payload = pad4(b"".join(records))
    return set_header(template_id, len(payload)) + payload, len(records)


def chunk(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def make_packets(nf9_events, ip256_events, ip258_events, base_ms,
                 late_templates):
    """Return the ordered list of (exporter_ip, bytes) datagrams."""
    packets = []
    nf9_seq = 0
    ip_seq = 0

    nf9_tmpl_sent = not late_templates
    ip258_tmpl_sent = not late_templates

    # Merge everything on virtual time, keeping per-exporter ordering.
    merged = []
    for ev in nf9_events:
        merged.append((ev["t"], "nf9", ev))
    for ev in ip256_events:
        merged.append((ev["t"], "ip256", ev))
    for ev in ip258_events:
        merged.append((ev["t"], "ip258", ev))
    merged.sort(key=lambda x: (x[0], x[1]))

    nf9_buf, ip256_buf, ip258_buf = [], [], []

    def flush_nf9():
        nonlocal nf9_seq
        if not nf9_buf:
            return
        flowsets = []
        for group in chunk(nf9_buf, 8):
            recs = [nf9_record(e, base_ms) for e in group]
            flowsets.append(data_flowset(256, recs))
        sysup = max(e["t"] for e in nf9_buf)
        pkt = nf9_packet(flowsets, nf9_seq, base_ms, sysup)
        nf9_seq += sum(n for _, n in flowsets)
        packets.append((NF9_EXPORTER, pkt))
        nf9_buf.clear()

    def flush_ip():
        nonlocal ip_seq
        if not ip256_buf and not ip258_buf:
            return
        flowsets = []
        for group in chunk(ip256_buf, 8):
            recs = [ipfix_256_record(e, base_ms) for e in group]
            flowsets.append(data_flowset(256, recs))
        for group in chunk(ip258_buf, 8):
            recs = [ipfix_258_record(e, base_ms) for e in group]
            flowsets.append(data_flowset(258, recs))
        pkt = ipfix_packet(flowsets, ip_seq, base_ms)
        ip_seq += sum(n for _, n in flowsets)
        packets.append((IPFIX_EXPORTER, pkt))
        ip256_buf.clear()
        ip258_buf.clear()

    for t, kind, ev in merged:
        if late_templates and not nf9_tmpl_sent and t >= NF9_TEMPLATE_GATE_MS:
            flush_nf9()
            packets.append((
                NF9_EXPORTER,
                nf9_packet([(nf9_template_256(), 0)], nf9_seq, base_ms),
            ))
            nf9_tmpl_sent = True
        if late_templates and not ip258_tmpl_sent and t >= IPFIX_258_GATE_MS:
            flush_ip()
            packets.append((
                IPFIX_EXPORTER,
                ipfix_packet(
                    [(ipfix_template_256(), 0), (ipfix_template_258(), 0)],
                    ip_seq,
                    base_ms,
                ),
            ))
            ip258_tmpl_sent = True

        if kind == "nf9":
            nf9_buf.append(ev)
        elif kind == "ip256":
            ip256_buf.append(ev)
        else:
            ip258_buf.append(ev)
        if len(nf9_buf) >= 24:
            flush_nf9()
        if len(ip256_buf) + len(ip258_buf) >= 24:
            flush_ip()

    # Templates first when late mode is off.
    if not late_templates:
        packets.insert(0, (
            IPFIX_EXPORTER,
            ipfix_packet(
                [(ipfix_template_256(), 0), (ipfix_template_258(), 0)],
                0,
                base_ms,
            ),
        ))
        packets.insert(0, (
            NF9_EXPORTER,
            nf9_packet([(nf9_template_256(), 0)], 0, base_ms),
        ))
    else:
        # IPFIX template 256 still goes out immediately; only 258 is delayed.
        packets.insert(0, (
            IPFIX_EXPORTER,
            ipfix_packet([(ipfix_template_256(), 0)], 0, base_ms),
        ))

    flush_nf9()
    flush_ip()
    return packets


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="127.0.0.1:2055",
                    help="collector host:port (default 127.0.0.1:2055)")
    ap.add_argument("--seed", type=int, default=20261116)
    ap.add_argument("--no-late-templates", action="store_true",
                    help="send every template before any data (default: delayed)")
    ap.add_argument("--pace", action="store_true",
                    help="pace sends along the virtual timeline (default: "
                         "sim mode, whole timeline sent in a few seconds)")
    ap.add_argument("--speed", type=float, default=60.0,
                    help="pace-mode time compression factor (default 60x)")
    ap.add_argument("--sleep-ms", type=int, default=2,
                    help="sim-mode delay between datagrams (default 2ms)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build packets but send nothing; print a summary")
    args = ap.parse_args()

    base_ms = int(time.time() * 1000)
    nf9_events, ip256_events, ip258_events = build_events(args.seed)
    packets = make_packets(
        nf9_events, ip256_events, ip258_events, base_ms,
        late_templates=not args.no_late_templates,
    )
    total_records = len(nf9_events) + len(ip256_events) + len(ip258_events)

    print(
        f"built {len(packets)} datagrams, {total_records} flow records "
        f"(NF9 {len(nf9_events)}, IPFIX-256 {len(ip256_events)}, "
        f"IPFIX-258 {len(ip258_events)}); late templates "
        f"{'off' if args.no_late_templates else 'on'}",
        file=sys.stderr,
    )
    if args.dry_run:
        sizes = sorted({len(p) for _, p in packets})
        print(f"datagram sizes: min={sizes[0]} max={sizes[-1]} bytes",
              file=sys.stderr)
        return

    host, port = args.target.rsplit(":", 1)
    # Two distinct ephemeral source ports emulate two exporting switches;
    # binding to the fictional 10.0.0.x addresses would fail on a host that
    # does not own them. The collector keys templates on the observed source.
    sock_nf9 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_ipfix = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_nf9.bind(("0.0.0.0", 0))
    sock_ipfix.bind(("0.0.0.0", 0))
    nf9_src_port = sock_nf9.getsockname()[1]
    ipfix_src_port = sock_ipfix.getsockname()[1]
    sources = {NF9_EXPORTER: sock_nf9, IPFIX_EXPORTER: sock_ipfix}
    sent = 0
    t0 = time.monotonic()
    base_mono = t0
    for exporter, pkt in packets:
        sources[exporter].sendto(pkt, (host, int(port)))
        sent += 1
        if args.pace:
            # Pace by datagram index across the compressed virtual timeline.
            target_elapsed = (sent / len(packets)) * (26 * 60) / args.speed
            drift = (base_mono + target_elapsed) - time.monotonic()
            if drift > 0:
                time.sleep(drift)
        else:
            time.sleep(args.sleep_ms / 1000.0)
    sock_nf9.close()
    sock_ipfix.close()
    elapsed = time.monotonic() - t0
    print(
        f"sent {sent} datagrams in {elapsed:.1f}s -> {args.target} "
        f"(sources {nf9_src_port}, {ipfix_src_port})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
