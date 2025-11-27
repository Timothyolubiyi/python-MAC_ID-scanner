# python-MAC_ID-scanner
Automated single and ready-to-run cross-platform Python script that discovers devices on your LAN and prints their IP and MAC addresses.



Below is a single, ready-to-run cross-platform Python script that discovers devices on your LAN and prints their IP and MAC addresses.

How it works (high level)

Finds your laptop’s local IP (by opening a UDP socket to the internet — no packets sent).

Derives the local network (tries to detect netmask; falls back to /24).

Option A: If scapy is installed and you run the script as root/Administrator, it uses an ARP scan (scapy.arping) — fastest and most reliable.

Option B: Otherwise it performs a simple ping sweep across the subnet to populate the ARP table and then parses arp -a (works on Windows/macOS/Linux).

Prints a table of discovered IP ⇢ MAC addresses.

Important safety & limitations

You must run this on the same Layer-2 network as the target devices (same LAN/subnet). This cannot find devices across routers.

Some devices may not respond to pings or ARP (firewall, privacy features), so they may not appear.

Running ARP scans typically requires elevated privileges (root / Administrator). The script will still try the arp -a fallback without root, but results may be limited.


