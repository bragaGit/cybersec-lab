#!/usr/bin/env python3
"""
extract_dns_exfil.py
Minimal, working DNS-exfil detection demo.
"""

import sys, re, base64
from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

def try_decodes(s):
    if isinstance(s, str):
        s = s.encode()
    results = {}
    # try base64/urlsafe/base32 with padding
    for name, fn in [
        ("base64", lambda b: base64.b64decode(b + b"===")),
        ("urlsafe_b64", lambda b: base64.urlsafe_b64decode(b + b"===")),
        ("base32", lambda b: base64.b32decode(b + b"====", casefold=True)),
    ]:
        try:
            out = fn(s)
            results[name] = out.decode(errors="ignore")
        except Exception:
            pass
    # hex
    if re.fullmatch(rb"[0-9A-Fa-f]+", s):
        try:
            results["hex"] = bytes.fromhex(s.decode()).decode(errors="ignore")
        except Exception:
            pass
    return results

def is_suspicious(qname):
    if not qname:
        return False
    q = qname.rstrip(".")
    labels = q.split(".")
    # old checks (lengths / label counts)
    if len(q) > 80 or any(len(lbl) > 32 for lbl in labels) or len(labels) > 6:
        return True
    # new: left label looks base64-like (chars + padding) and length >= 6
    left = labels[0] if labels else ""
    if len(left) >= 6 and re.fullmatch(r'[A-Za-z0-9\-_=/+]+', left):
        return True
    return False

def extract(path):
    pkts = rdpcap(path)
    out = []
    for p in pkts:
        if not (p.haslayer(DNS) and p[DNS].qr == 0):
            continue
        try:
            qn = p[DNSQR].qname.decode()
        except Exception:
            continue
        src = p[IP].src if p.haslayer(IP) else "?"
        dst = p[IP].dst if p.haslayer(IP) else "?"
        if is_suspicious(qn):
            out.append((src, dst, qn))
    return out

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_dns_exfil.py file.pcap")
        sys.exit(1)
    path = sys.argv[1]
    print(f"[+] Reading {path}")
    suspects = extract(path)
    print(f"[+] Suspicious DNS queries: {len(suspects)}")
    for i, (src, dst, qn) in enumerate(suspects, 1):
        print(f"\n[{i}] {src} -> {dst}")
        print("QNAME:", qn)
        label = qn.split(".")[0]
        decs = try_decodes(label)
        for k,v in decs.items():
            print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
