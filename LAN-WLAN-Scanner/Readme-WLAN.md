## Advanced LAN-WLAN MAC Scanner ##

A powerful and intelligent network discovery tool for scanning LAN/WLAN environments. The scanner identifies devices using ARP, ping-sweep, hostname resolution, and OUI vendor lookup to give deep insight into all connected devices.

## Overview ##

The Advanced LAN-WLAN MAC Scanner is a cross-platform Python tool designed to scan local networks and retrieve comprehensive device information including:

- IP Address

- MAC Address

- OEM Vendor Name (via OUI lookup)

- Hostname (reverse DNS)

- IP Type (Private/Public)

- It includes both a command-line interface (CLI) and a Tkinter graphical user interface (GUI) for versatile usage.

## Features ##
## 🔍 Comprehensive Network Scanning ##

- ARP-based scanning using Scapy (fastest, requires privileges)

- Ping-sweep scanning fallback (works without root/admin)

## 🏭 MAC Vendor (OUI) Lookup ##

- Detects device manufacturers (Apple, Cisco, Intel, etc.)

- Auto-downloads and caches the IEEE OUI database

## 🌐 Hostname Resolution ##

High-speed multi-threaded reverse DNS lookup

Optional disabling for faster scans

## ⚡ Optimized Performance ##

- Multi-threaded scanning

- Supports large IP ranges with configurable limits

- Auto-detects local network interface and subnet

## 🖥️ GUI Mode (Tkinter) ##

- Real-time scan progress

- Visual device table

- Export buttons (CSV, JSON)

- IP range input, interface selector, DNS toggle

## 💾 Export Options ##

- JSON export with metadata

- CSV export of all scan results

- Export from either CLI or GUI

## Installation ##
# Requirements

- Python 3.7+

- Tkinter (preinstalled on most systems)

# Optional Dependencies #
 pip install scapy psutil

## Setup & Running ##

1. # Clone or download the project:

cd python-MAC_ID-scanner/MAC-ID-fullscan/


2. # (Optional but recommended) Install dependencies:

pip install scapy psutil


Run:

python wlan_mac_scanner_full.py     # CLI mode
python wlan_mac_scanner_full.py --gui   # GUI mode
python wlan_mac_scanner_full.py --interface eth0  # specify interface
python wlan_mac_scanner_full.py --max-hosts 1000 # Limit large networks
python wlan_mac_scanner_full.py --no-scapy  # Disable Scapy
python wlan_mac_scanner_full.py --range 192.168.1.0/24 --json out.json --csv out.csv  # Full scan with exports




## Usage Guide ##
# CLI Mode #
1. # Auto-detect and scan:
python wlan_mac_scanner_full.py

2. # Scan a specific CIDR:
python wlan_mac_scanner_full.py --range 192.168.1.0/24

3. # Scan an IP range:
python wlan_mac_scanner_full.py --range 192.168.1.10-192.168.1.50

4. # Disable hostname lookup:
python wlan_mac_scanner_full.py --no-dns

5. # Export to JSON:
python wlan_mac_scanner_full.py --json output.json

6. # Export to CSV:
python wlan_mac_scanner_full.py --csv output.csv

## Combine options:
python wlan_mac_scanner_full.py --range 192.168.1.0/24 \
    --csv results.csv \
    --json results.json \
    --no-dns

## GUI Features ##

- Select network interface

- Enter CIDR or range

- Enable/disable hostname lookup

- Real-time scanning progress

- Full results table

- Export to CSV/JSON

- Clear or quit application

### Output Formats ###

<img width="968" height="224" alt="Image" src="https://github.com/user-attachments/assets/320104b4-9a8f-43b8-afcc-d40c53cc0acb" />

### JSON Format ###

<img width="988" height="407" alt="Image" src="https://github.com/user-attachments/assets/c68a32d7-5aba-466d-9f5d-6741affcdc54" />

### GUI Interface ###

<img width="1787" height="847" alt="Image" src="https://github.com/user-attachments/assets/655bc831-550a-4989-92ab-b43c6a68c9ef" />


### GUI Interfaces Selection ####

<img width="1780" height="520" alt="Image" src="https://github.com/user-attachments/assets/1b47c697-220d-4acd-951e-7e2b2a3cc656" />


## How the Scanner Works  ##
1. Scapy ARP Scan (Preferred)

- Sends ARP requests to all IPs

- Reads ARP responses

- Fastest and most accurate

- Requires root/admin

2. Ping Sweep Fallback

- Sends concurrent ping requests

- Populates ARP table

- Parses OS ARP table for results

- Works without privileges

### Platform Compatibility ###

<img width="894" height="216" alt="Image" src="https://github.com/user-attachments/assets/3b9096c3-5006-47bc-b1eb-06121b6761f1" />



## Security Warning ##

Scanning networks may require authorization.
Always ensure you have permission before scanning any network.