#!/usr/bin/env python3
"""
network_watchdog_risk.py

Suspicious network activity detector with RISK SCORING.
Analyzes a pcap or a live capture and reports:
 - DNS exfil candidates (base64/base32/hex-looking subdomain labels)
 - Port scans (many distinct dst ports in short window)
 - SYN scan / incomplete handshakes
 - Large flows (bytes by 5-tuple)
 - Beaconing (regular contact intervals)
 - Risk score per source IP (0–100) with severity

Usage:
  Offline: python3 network_watchdog_risk.py --pcap traffic.pcapng
  Live 60s: sudo python3 network_watchdog_risk.py --iface en0 --duration 60
"""

import argparse, re, base64, statistics, time
from collections import defaultdict, Counter
from datetime import datetime
import numpy as np
import pandas as pd

from scapy.all import rdpcap, PcapReader, sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

# -------- Tunable thresholds --------
PORT_SCAN_PORT_THRESHOLD = 30       # distinct dst ports in window
PORT_SCAN_TIME_WINDOW_S   = 60
INCOMPLETE_SYN_THRESHOLD  = 25      # SYNs without completion (approx.)
LARGE_FLOW_BYTES          = 1_000_000
BEACON_MIN_EVENTS         = 6
BEACON_COV_THRESHOLD      = 0.25    # lower = more regular (beacon-y)
DNS_LEFTLABEL_MINLEN      = 6
# -------- Risk weights --------------
W_DNS_EXFIL         = 25
W_PORT_SCAN         = 30
W_SYN_SCAN          = 25
W_LARGE_FLOW        = 15
W_BEACON            = 20
MAX_RISK_PER_SRC    = 100
# ------------------------------------

BASE64_LIKE_RE = re.compile(r'^[A-Za-z0-9\-_=/+]+$')
HEX_RE         = re.compile(r'^[0-9A-Fa-f]+$')

def try_decodes_label(label: str):
    """Attempt base64/urlsafe/base32/hex on a label; return dict of successes."""
    out = {}
    b = label.encode() if isinstance(label, str) else label
    for name, fn in (
        ("base64",      lambda x: base64.b64decode(x + b"===")),
        ("urlsafe_b64", lambda x: base64.urlsafe_b64decode(x + b"===")),
        ("base32",      lambda x: base64.b32decode(x + b"====", casefold=True)),
    ):
        try:
            dec = fn(b)
            txt = dec.decode("utf-8", errors="ignore")
            out[name] = txt if txt.strip() else dec.hex()
        except Exception:
            pass
    if __import__('re').fullmatch(rb'[0-9A-Fa-f]+', b):
        try:
            dec = bytes.fromhex(b.decode())
            txt = dec.decode("utf-8", errors="ignore")
            out["hex"] = txt if txt.strip() else dec.hex()
        except Exception:
            pass
    return out

def collect_packets_from_pcap(path):
    try:
        with PcapReader(path) as r:
            return list(r)
    except Exception:
        return list(rdpcap(path))

def collect_packets_live(iface: str, duration: int):
    # Live capture (needs sudo). Keep small duration for safety.
    pkts = sniff(iface=iface, timeout=duration, store=True)
    return list(pkts)

def analyze_packets(pkts):
    dns_events, syn_events, conn_events = [], [], []
    flow_bytes = defaultdict(int)  # (src,dst,sport,dport,proto) -> bytes

    for pkt in pkts:
        ts = getattr(pkt, "time", None)
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            try:
                qn = pkt[DNSQR].qname.decode(errors="ignore")
            except Exception:
                qn = str(pkt[DNSQR].qname)
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            dns_events.append({"time": ts, "src": src, "dst": dst, "qname": qn})

        if pkt.haslayer(IP):
            src = pkt[IP].src; dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
                conn_events.append({"time": ts, "src": src, "dst": dst, "sport": tcp.sport, "dport": tcp.dport, "proto": "TCP", "len": payload_len})
                if tcp.flags & 0x02:  # SYN
                    syn_events.append({"time": ts, "src": src, "dst": dst, "dport": tcp.dport})
                flow_bytes[(src, dst, tcp.sport, tcp.dport, "TCP")] += payload_len
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                payload_len = len(bytes(udp.payload)) if udp.payload else 0
                conn_events.append({"time": ts, "src": src, "dst": dst, "sport": udp.sport, "dport": udp.dport, "proto": "UDP", "len": payload_len})
                flow_bytes[(src, dst, udp.sport, udp.dport, "UDP")] += payload_len

    dns_df = pd.DataFrame(dns_events)
    syn_df = pd.DataFrame(syn_events)
    conn_df = pd.DataFrame(conn_events)

    # ---- DNS exfil candidates ----
    dns_candidates = []
    if not dns_df.empty:
        for _, row in dns_df.iterrows():
            qn = row["qname"]
            left = qn.rstrip(".").split(".")[0] if isinstance(qn, str) else ""
            if not left: continue
            if (len(left) >= DNS_LEFTLABEL_MINLEN and BASE64_LIKE_RE.match(left)) or HEX_RE.match(left):
                decs = try_decodes_label(left)
                if decs:
                    dns_candidates.append({
                        "time": row["time"], "src": row["src"], "dst": row["dst"],
                        "qname": qn, "left_label": left, "decodings": decs
                    })

    # ---- Port scans & SYN scans ----
    scans = []
    incomplete = []
    if not syn_df.empty:
        syn_df = syn_df.sort_values("time")
        # sliding window per (src,dst)
        by_pair = syn_df.groupby(["src","dst"])
        for (src,dst), g in by_pair:
            times = list(g["time"])
            ports = list(g["dport"])
            i = 0
            n = len(times)
            while i < n:
                start_t = times[i]
                j = i
                seen = set()
                while j < n and (times[j] - start_t) <= PORT_SCAN_TIME_WINDOW_S:
                    seen.add(ports[j]); j += 1
                if len(seen) >= PORT_SCAN_PORT_THRESHOLD:
                    scans.append({"src":src,"dst":dst,"start":start_t,"distinct_ports":len(seen)})
                    i = j
                else:
                    i += 1
        # incomplete handshakes (approx): many SYNs to same dst:port
        syn_counts = syn_df.groupby(["src","dst","dport"]).size()
        for (src,dst,dport), cnt in syn_counts.items():
            if cnt >= INCOMPLETE_SYN_THRESHOLD:
                incomplete.append({"src":src,"dst":dst,"dport":int(dport),"syn_count":int(cnt)})

    # ---- Large flows ----
    large_flows = []
    for (src,dst,sport,dport,proto), b in flow_bytes.items():
        if b >= LARGE_FLOW_BYTES:
            large_flows.append({"src":src,"dst":dst,"sport":sport,"dport":dport,"proto":proto,"bytes":int(b)})

    # ---- Beaconing ----
    beacons = []
    if not conn_df.empty:
        conn_df = conn_df.sort_values("time")
        by_pair = conn_df.groupby(["src","dst"])
        for (src,dst), g in by_pair:
            times = [t for t in g["time"] if t is not None]
            if len(times) < BEACON_MIN_EVENTS: continue
            intervals = np.diff(sorted(times))
            if len(intervals) < 3: continue
            mean = float(np.mean(intervals)); sd = float(np.std(intervals))
            cov = sd / (mean + 1e-9)
            if cov < BEACON_COV_THRESHOLD:
                beacons.append({"src":src,"dst":dst,"count":len(times),"mean_interval_s":mean,"cov":cov})

    return {
        "dns_candidates": dns_candidates,
        "scans": scans,
        "incomplete": incomplete,
        "large_flows": large_flows,
        "beacons": beacons
    }

def score_and_summarize(findings):
    risk = defaultdict(int)
    notes = defaultdict(list)

    for c in findings["dns_candidates"]:
        risk[c["src"]] += W_DNS_EXFIL
        notes[c["src"]].append(f"DNS exfil-candidate qname={c['qname']}")
    for s in findings["scans"]:
        risk[s["src"]] += W_PORT_SCAN
        notes[s["src"]].append(f"Port scan to {s['dst']} ({s['distinct_ports']} ports)")
    for inc in findings["incomplete"]:
        risk[inc["src"]] += W_SYN_SCAN
        notes[inc["src"]].append(f"SYN scan? to {inc['dst']}:{inc['dport']} (SYNs={inc['syn_count']})")
    for lf in findings["large_flows"]:
        risk[lf["src"]] += W_LARGE_FLOW
        notes[lf["src"]].append(f"Large flow to {lf['dst']}:{lf['dport']} bytes={lf['bytes']}")
    for b in findings["beacons"]:
        risk[b["src"]] += W_BEACON
        notes[b["src"]].append(f"Beaconing to {b['dst']} (count={b['count']}, mean={b['mean_interval_s']:.1f}s, cov={b['cov']:.2f})")

    # cap and classify
    table = []
    for src, score in risk.items():
        s = min(score, MAX_RISK_PER_SRC)
        if s >= 80: sev = "CRITICAL"
        elif s >= 60: sev = "HIGH"
        elif s >= 30: sev = "MEDIUM"
        else: sev = "LOW"
        table.append({"src": src, "risk": s, "severity": sev, "indicators": "; ".join(notes[src])})

    table = sorted(table, key=lambda r: r["risk"], reverse=True)
    return table

def print_report(findings, risks, limit=10):
    print("\n=== THREAT SUMMARY (Top sources by risk) ===")
    if not risks:
        print("No suspicious indicators detected.")
    else:
        for r in risks[:limit]:
            print(f"{r['src']}: RISK {r['risk']} [{r['severity']}]")
            print(f"  {r['indicators']}")
    # Detail counts
    print("\n=== INDICATOR COUNTS ===")
    print(f"DNS exfil candidates: {len(findings['dns_candidates'])}")
    print(f"Port scans: {len(findings['scans'])}")
    print(f"Incomplete handshakes (SYN scans): {len(findings['incomplete'])}")
    print(f"Large flows (> {LARGE_FLOW_BYTES} bytes): {len(findings['large_flows'])}")
    print(f"Beaconing candidates: {len(findings['beacons'])}")

def write_csvs(findings, risks):
    # Write CSVs for triage
    if findings["dns_candidates"]:
        rows=[]
        for c in findings["dns_candidates"]:
            rows.append({
                "time": c["time"], "src": c["src"], "dst": c["dst"],
                "qname": c["qname"], "left_label": c["left_label"], "decodings": str(c["decodings"])
            })
        pd.DataFrame(rows).to_csv("dns_candidates.csv", index=False)
        print("Wrote dns_candidates.csv")

    if findings["scans"]:
        pd.DataFrame(findings["scans"]).to_csv("port_scans.csv", index=False); print("Wrote port_scans.csv")
    if findings["incomplete"]:
        pd.DataFrame(findings["incomplete"]).to_csv("syn_scans.csv", index=False); print("Wrote syn_scans.csv")
    if findings["large_flows"]:
        pd.DataFrame(findings["large_flows"]).to_csv("large_flows.csv", index=False); print("Wrote large_flows.csv")
    if findings["beacons"]:
        pd.DataFrame(findings["beacons"]).to_csv("beacons.csv", index=False); print("Wrote beacons.csv")
    if risks:
        pd.DataFrame(risks).to_csv("threat_summary.csv", index=False); print("Wrote threat_summary.csv")

def main():
    ap = argparse.ArgumentParser(description="Detect suspicious activities with risk scoring")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Path to pcap/pcapng file")
    src.add_argument("--iface", help="Interface for live capture (requires sudo)")
    ap.add_argument("--duration", type=int, default=60, help="Live capture seconds (default 60)")
    ap.add_argument("--no-csv", action="store_true", help="Do not write CSV outputs")
    args = ap.parse_args()

    if args.pcap:
        pkts = collect_packets_from_pcap(args.pcap)
        print(f"[+] Loaded {len(pkts)} packets from {args.pcap}")
    else:
        print(f"[+] Sniffing {args.duration}s on {args.iface} (need sudo)")
        pkts = collect_packets_live(args.iface, args.duration)
        print(f"[+] Captured {len(pkts)} packets")

    findings = analyze_packets(pkts)
    risks = score_and_summarize(findings)
    print_report(findings, risks)
    if not args.no_csv:
        write_csvs(findings, risks)

if __name__ == "__main__":
    main()

