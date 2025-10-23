# Cybersec Lab — Network Watchdog

Detection scripts for DNS exfiltration, port scans, beaconing, and more.

## Quick start
To run locally:

    python3 -m venv .venv
    source .venv/bin/activate
    python3 -m pip install -r requirements.txt
    python3 network_watchdog_risk.py --pcap sample.pcap

## Features
- Detects DNS exfiltration attempts
- Flags port and SYN scans
- Finds large data transfers
- Detects periodic beaconing (C2 activity)
- Provides risk scoring and threat summary

## License
MIT License © 2025 Anderson
