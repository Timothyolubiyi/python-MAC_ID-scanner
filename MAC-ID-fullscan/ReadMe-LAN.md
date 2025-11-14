I built a single, ready-to-run Python program that adds everything you asked for:

continuous background scanner (ARP with scapy, fallback to ping+arp)

automatic interface selection (prefer LAN, fallback to Wi-Fi)

device vendor lookup (MAC → manufacturer) with automatic OUI download & local cache

SQLite logging of device sightings with timestamps (detects join/leave)

export endpoints (CSV / JSON / TXT) and manual exports from CLI

a Web Dashboard (Flask) showing live device list and an interactive network topology map (uses vis-network from CDN)

simple API for live updates (dashboard polls every 5s)

optional Tkinter GUI launcher that opens dashboard in browser

CLI controls to run scanner-only, web dashboard, or both


# Requirements

$ Install dependencies (recommended in a venv):

$ pip install scapy flask requests python-dateutil psutil
# scapy may require additional OS deps on Linux (libpcap) and Admin/root to use ARP.


On Linux/macOS run scanner parts with sudo for scapy ARP scans. Without root, fallback still works.

Windows: run the script from an Administrator shell for best ARP results.


# Quick usage

Start the full dashboard + scanner (recommended):

$ python lan_dashboard.py --serve
*** Open http://127.0.0.1:5000 in your browser ***

# Start only the scanner (no web dashboard):

$ python lan_dashboard.py --scan-only

# Run GUI launcher (opens dashboard in browser):

$ python lan_dashboard.py --gui

# Export logged results to CSV/JSON/TXT (from CLI):

$ python lan_dashboard.py --export csv devices.csv
$ python lan_dashboard.py --export json devices.json
$ python lan_dashboard.py --export txt devices.txt


# Force (re)download OUI database:

python lan_dashboard.py --update-oui


#### What the dashboard shows

- Live list of discovered devices (IP, MAC, Vendor, first seen, last seen, status online/offline)

- Interactive topology graph showing your gateway and devices (drag nodes, zoom)

- Buttons to export current view to CSV/JSON/TXT

- Real-time updates every 5 seconds


## Notes, caveats & tips

ARP scans require elevated privileges for scapy. If you run without admin privileges the script falls back to ping + parsing the OS ARP table. That still finds most hosts on a local LAN.

OUI vendor data is pulled from IEEE (if requests is installed). If you work offline, you can manually place an oui.txt in ~/.lan_dashboard/oui.txt and the script will use it.

Topology in the dashboard is simple: gateway node connected to all devices. If you want richer topology (switches, multiple subnets, L2 topology), that requires SNMP or managed-switch querying — I can add SNMP discovery next.

Device join/leave detection is based on whether a MAC is seen in the most recent scan(s). You can tune SCAN_INTERVAL.

Background logging persists across reboots via SQLite (~/.lan_dashboard/devices.db).