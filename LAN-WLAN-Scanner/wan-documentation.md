
# Advanced LAN MAC Scanner

An enhanced network device scanner that discovers and identifies devices on your local network with detailed information including IP addresses, MAC addresses, OEM vendor names, and hostnames.

## Features

✨ **New & Enhanced Features:**
- 🎯 **OUI Vendor Lookup** — Automatically identifies device manufacturers (Apple, Cisco, Intel, etc.) from MAC addresses using IEEE OUI database
- 🌐 **Hostname Resolution** — Performs reverse DNS lookups to display device hostnames
- 🔍 **IP Type Detection** — Distinguishes between private and public IP addresses
- 📊 **Advanced Scanning** — Supports both Scapy ARP scanning and fallback ping-sweep method
- 💾 **Rich Exports** — Export scan results to JSON and CSV with all enriched data (IP, MAC, Vendor, Hostname)
- 🖥️ **GUI Application** — Tkinter-based graphical interface with real-time progress
- ⚡ **Concurrent Operations** — Multi-threaded hostname resolution and pinging for speed
- 🎛️ **Flexible Configuration** — Scan by CIDR, IP ranges, or auto-detect local network

## Installation

### Requirements
- Python 3.7+
- `tkinter` (included with most Python distributions)
- Optional: `scapy` (for native ARP scanning with root/admin privileges)
- Optional: `psutil` (for network interface enumeration)

### Setup

```bash
# Clone or download the scanner
cd python-MAC_ID-scanner/MAC-ID-fullscan/

# Install optional dependencies (recommended)
pip install scapy psutil

# Run the scanner
python wlan_mac_scanner_full.py --gui
```

## Usage

### CLI Mode

**Basic scan (auto-detects local network):**
```bash
python wlan_mac_scanner_full.py
```

**Scan specific network:**
```bash
python wlan_mac_scanner_full.py --range 192.168.1.0/24
```

**Scan IP range:**
```bash
python wlan_mac_scanner_full.py --range 192.168.1.10-192.168.1.50
```

**Skip hostname resolution (faster):**
```bash
python wlan_mac_scanner_full.py --no-dns
```

**Export to JSON:**
```bash
python wlan_mac_scanner_full.py --json scan_results.json
```

**Export to CSV:**
```bash
python wlan_mac_scanner_full.py --csv scan_results.csv
```

**Combine options:**
```bash
python wlan_mac_scanner_full.py --range 192.168.1.0/24 --csv results.csv --json results.json --no-dns
```

### GUI Mode

```bash
python wlan_mac_scanner_full.py --gui
```

**GUI Features:**
1. **Interface Selection** — Choose network interface to scan from (auto-detected)
2. **Range Input** — Enter custom CIDR or start-end IP range
3. **Hostname Resolution Toggle** — Enable/disable DNS lookups (toggle before scan)
4. **Real-Time Progress** — Visual feedback during scanning
5. **Results Table** — Displays IP, MAC, Vendor, Hostname, and Type columns
6. **Export Functions** — Save results as JSON or CSV with full device details
7. **Clear & Quit** — Clear results or exit the application

## Output Format

### Console Output
```
Discovered devices:
IP              MAC                Vendor (OEM)                  Hostname              Type
---------------------------------------------------------------------------
192.168.1.1     aa:bb:cc:dd:ee:ff   Cisco Systems Inc            router.local          Private
192.168.1.50    11:22:33:44:55:66   Apple Inc.                   macbook.local         Private
192.168.1.100   44:55:66:77:88:99   Intel Corp.                  (no hostname)         Private
```

### CSV Export
```csv
IP,MAC,Vendor (OEM),Hostname,IP Type
192.168.1.1,aa:bb:cc:dd:ee:ff,Cisco Systems Inc,router.local,Private
192.168.1.50,11:22:33:44:55:66,Apple Inc.,macbook.local,Private
192.168.1.100,44:55:66:77:88:99,Intel Corp.,(no hostname),Private
```

### JSON Export
```json
{
  "scanned_at": "2025-11-26T14:23:45.123456Z",
  "results": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "vendor": "Cisco Systems Inc",
      "hostname": "router.local",
      "ip_type": "Private"
    },
    {
      "ip": "192.168.1.50",
      "mac": "11:22:33:44:55:66",
      "vendor": "Apple Inc.",
      "hostname": "macbook.local",
      "ip_type": "Private"
    }
  ]
}
```

## How It Works

### Scanning Methods

1. **Scapy ARP Scan** (Preferred — requires admin/root)
   - Native ARP requests to discover devices
   - Fastest and most reliable method
   - Requires elevated privileges

2. **Ping Sweep Fallback** (No privileges required)
   - Pings all IPs in target range concurrently (100 threads by default)
   - Populates system ARP table
   - Parses ARP table to extract discovered devices
   - Works on Windows, macOS, and Linux

### Vendor Lookup (OUI Database)

- Downloads IEEE OUI database on first run (~1.5 MB)
- Caches database at `~/.cache/oui.txt`
- Extracts first 3 octets (6 hex chars) of MAC address
- Matches against 30,000+ registered vendors
- Gracefully falls back to "Unknown" if database unavailable

### Hostname Resolution

- Performs concurrent reverse DNS lookups (50 threads default)
- Uses `socket.gethostbyaddr()` with 1-second timeout
- Non-blocking — slow/unresponsive devices don't block scanning
- Results displayed even if hostname lookup fails

## Performance

### Scan Time Estimates

| Network Size | Method | Time (approx) |
|---|---|---|
| /24 (254 hosts) | Scapy | 2-5 seconds |
| /24 (254 hosts) | Ping Sweep | 10-30 seconds |
| /25 (126 hosts) | Scapy | 1-3 seconds |
| /25 (126 hosts) | Ping Sweep | 5-15 seconds |

**Optimization Tips:**
- Use `--no-dns` flag to skip hostname resolution (saves 30-50% time)
- Use Scapy if possible (run with `sudo` on Linux/macOS)
- Smaller networks (`/25` or `/26`) scan much faster
- Use specific IP ranges instead of large subnets

## Platform Compatibility

| OS | Status | Notes |
|---|---|---|
| Windows | ✅ Full support | Requires admin for Scapy; ping works as regular user |
| macOS | ✅ Full support | Use `sudo` for best results with Scapy |
| Linux | ✅ Full support | Use `sudo` for Scapy ARP scanning |

## Troubleshooting

### "Permission denied" with Scapy
- **Linux/macOS:** Run with `sudo`: `sudo python wlan_mac_scanner_full.py`
- **Windows:** Run Command Prompt as Administrator

### No devices found
1. Check your network connection
2. Ensure correct IP range (e.g., `192.168.1.0/24` not `192.168.1.255/32`)
3. Try with `--no-dns` flag
4. Check firewall rules aren't blocking pings
5. Try `--no-scapy` to force fallback method

### OUI database download fails
- Scanner still works but shows "Unknown" for all vendors
- Manual download: `curl http://standards-oui.ieee.org/oui/oui.txt > ~/.cache/oui.txt`
- Or remove cache: `rm ~/.cache/oui.txt` and re-run

### Hostname lookup very slow
- Use `--no-dns` flag to skip
- Check DNS server is responsive: `nslookup 8.8.8.8`

## Advanced Options

### Custom Interface
```bash
python wlan_mac_scanner_full.py --interface eth0
```

### Large Network Scanning
```bash
# Limit to first 1000 hosts (safety default)
python wlan_mac_scanner_full.py --range 10.0.0.0/16 --max-hosts 1000
```

### Disable Scapy
```bash
python wlan_mac_scanner_full.py --no-scapy
```

## Examples

### Find all Apple devices on network
```bash
python wlan_mac_scanner_full.py --csv devices.csv
# Then filter: grep -i apple devices.csv
```

### Scan and export everything
```bash
python wlan_mac_scanner_full.py --range 192.168.1.0/24 \
  --json results.json \
  --csv results.csv
```

### Fast scan without DNS resolution
```bash
python wlan_mac_scanner_full.py --no-dns
```

### Interactive GUI scan
```bash
python wlan_mac_scanner_full.py --gui
```

## Security Note

This tool requires network access and may trigger security alerts on monitored networks. Always ensure you have permission before scanning networks you don't own.

## Dependencies

### Built-in (no installation needed)
- `socket`, `subprocess`, `re`, `ipaddress`, `argparse`, `json`, `csv`, `concurrent.futures`, `threading`, `pathlib`, `urllib`
- `tkinter` (usually pre-installed with Python)

### Optional (recommended)
```bash
pip install scapy psutil
```

## License

Open source — use and modify as needed.

## Version

Advanced LAN MAC Scanner v2.0
Enhanced with OUI vendor lookup, hostname resolution, and improved UI.

---

**Last Updated:** November 2025
