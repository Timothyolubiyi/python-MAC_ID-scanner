I made a single, all-in-one Python script that includes everything you asked for:

CLI and Tkinter GUI modes (use --gui to open the GUI)

Optional JSON (--json OUTFILE) and CSV (--csv OUTFILE) export

Option to scan a specific IP range or network (--range 192.168.1.0/24 or --range 192.168.1.5-192.168.1.50)

Option to pick a specific interface (attempts to enumerate interfaces)

Uses scapy ARP scan if scapy is available and allowed, otherwise falls back to ping sweep + ARP table parsing (cross-platform)

Shows results (IP ⇢ MAC) in console and in the GUI table; GUI supports export buttons

Save as lan_mac_scanner_full.py and run with Python 3.8+.

Important: ARP-based scanning is local-L2 only — it only finds devices on the same LAN/subnet. ARP scanning usually requires elevated privileges (root / Administrator) for scapy. Use caution — scanning networks you don't control may violate policy.

Usage examples

# CLI full scan (auto-detect network):
python lan_mac_scanner_full.py

# CLI scan specific network and export CSV:
python lan_mac_scanner_full.py --range 192.168.1.0/24 --csv results.csv

# GUI:
python lan_mac_scanner_full.py --gui

# Specify interface:
python lan_mac_scanner_full.py --interface eth0