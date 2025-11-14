#!/usr/bin/env python3
"""
lan_dashboard.py — LAN scanner + vendor lookup + web dashboard + logger

Features:
 - Runs continuous LAN scan (scapy ARP preferred; ping+arp fallback)
 - Auto-detect LAN/Ethernet interface (with Wi-Fi fallback)
 - Vendor lookup using IEEE OUI file (auto-download & cache)
 - Logs device sightings to SQLite; detects join/leave events
 - Flask web dashboard with interactive topology (vis-network via CDN)
 - CLI exports (csv/json/txt)
"""

import os
import sys
import time
import json
import sqlite3
import threading
import ipaddress
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from argparse import ArgumentParser

# optional modules
try:
    from scapy.all import arping, conf  # type: ignore
    SCAPY = True
except Exception:
    SCAPY = False

try:
    import requests
except Exception:
    requests = None

try:
    import psutil
except Exception:
    psutil = None

# flask
try:
    from flask import Flask, jsonify, request, send_file, render_template_string, abort
except Exception:
    Flask = None

# date parsing for nice ISO times
try:
    from dateutil import tz
except Exception:
    tz = None

APP_DIR = Path.home() / ".lan_dashboard"
APP_DIR.mkdir(parents=True, exist_ok=True)
OUI_FILE = APP_DIR / "oui.txt"
DB_FILE = APP_DIR / "devices.db"

# OUI source (IEEE)
OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"

# scanning settings
SCAN_INTERVAL = 12        # seconds between background scans
PING_TIMEOUT = 1000       # ping timeout ms (fallback ping)
MAX_HOSTS_SCAN = 1024     # safety cap on very large subnets

# ---------- Utilities ----------

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()

def debug_log(msg):
    print(f"[{datetime.now().isoformat()}] {msg}", flush=True)

# ---------- OUI / Vendor lookup ----------

def download_oui(force=False):
    """Download or refresh the IEEE OUI file if requests available."""
    if OUI_FILE.exists() and not force:
        return True
    if requests is None:
        debug_log("requests not installed: cannot download OUI database.")
        return False
    try:
        debug_log("Downloading OUI database from IEEE...")
        r = requests.get(OUI_URL, timeout=30)
        r.raise_for_status()
        OUI_FILE.write_text(r.text, encoding="utf-8")
        debug_log(f"Saved OUI file to {OUI_FILE}")
        return True
    except Exception as e:
        debug_log(f"Failed to download OUI file: {e}")
        return False

def load_oui_map():
    """Parse oui.txt into {prefix -> vendor} mapping (prefix like '00:11:22')."""
    if not OUI_FILE.exists():
        download_oui()
    mapping = {}
    if not OUI_FILE.exists():
        return mapping
    text = OUI_FILE.read_text(encoding="utf-8", errors="ignore")
    for line in text.splitlines():
        # lines with " (hex) " or similar: '00-00-00   (hex)    XEROX CORPORATION'
        # Common formats include '00-00-00   (hex)        XEROX CORPORATION'
        parts = line.strip().split()
        if "(hex)" in line:
            try:
                prefix = parts[0].replace('-', ':').upper()
                vendor = " ".join(parts[2:]).strip()
                mapping[prefix] = vendor
            except Exception:
                continue
        else:
            # some lines like '0050C2   (base 16)    VMware, Inc.'
            if len(parts) >= 3 and parts[0].isalnum() and parts[1].startswith('('):
                prefix_raw = parts[0]
                # split every 2 chars
                p = ":".join(prefix_raw[i:i+2] for i in range(0, len(prefix_raw), 2)).upper()
                vendor = " ".join(parts[2:]).strip()
                mapping[p] = vendor
    return mapping

OUI_MAP = load_oui_map()

def mac_to_vendor(mac):
    """Return vendor string from MAC address using OUI_MAP; mac expected like aa:bb:cc:dd:..."""
    if not mac:
        return "Unknown"
    m = mac.replace('-', ':').upper()
    # take first 3 octets
    parts = m.split(':')
    if len(parts) < 3:
        return "Unknown"
    prefix = ":".join(parts[:3])
    # try full, then progressively shorter matches
    if prefix in OUI_MAP:
        return OUI_MAP[prefix]
    # try uppercase with no leading zeros? Map keys are normalized though
    return OUI_MAP.get(prefix, "Unknown")

# ---------- Interface detection ----------

def get_interfaces_text():
    try:
        if platform.system() == "Windows":
            return subprocess.check_output(["ipconfig"], universal_newlines=True, stderr=subprocess.DEVNULL)
        else:
            # prefer ip addr if available
            try:
                return subprocess.check_output(["ip", "addr"], universal_newlines=True, stderr=subprocess.DEVNULL)
            except Exception:
                return subprocess.check_output(["ifconfig"], universal_newlines=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""

def detect_primary_interface(prefer_lan=True):
    """
    Attempt to detect physical LAN/Ethernet interface.
    Returns tuple (if_name, ip_addr, netmask_or_cidr)
    """
    if psutil:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        candidates = []
        for ifname, addr_list in addrs.items():
            if not stats.get(ifname) or not stats[ifname].isup:
                continue
            for a in addr_list:
                if a.family == getattr(socket, "AF_INET", 2):
                    ip = a.address
                    netmask = a.netmask
                    # prefer interfaces whose name suggests Ethernet
                    lname = ifname.lower()
                    score = 0
                    if "eth" in lname or "en" in lname or "ethernet" in lname:
                        score += 50
                    if "wi" in lname or "wl" in lname or "wlan" in lname or "wifi" in lname:
                        score += 10
                    candidates.append((score, ifname, ip, netmask))
        if candidates:
            # sort by score desc
            candidates.sort(reverse=True)
            best = candidates[0]
            return best[1], best[2], best[3]
    # fallback: parse textual output
    txt = get_interfaces_text()
    # look for IPv4 lines
    ip = None
    mask = None
    if platform.system() == "Windows":
        for line in txt.splitlines():
            if "IPv4 Address" in line or "IPv4-adres" in line:
                ip = line.split(":")[-1].strip()
            if "Subnet Mask" in line:
                mask = line.split(":")[-1].strip()
            if ip and mask:
                return ("detected", ip, mask)
    else:
        # look for 'inet ' lines
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                # format: inet 192.168.1.6/24 ...
                try:
                    parts = line.split()
                    addr = parts[1]
                    if '/' in addr:
                        ip_str, cidr = addr.split('/')
                        return ("detected", ip_str, cidr)
                except Exception:
                    continue
    return (None, None, None)

# ---------- SQLite logging ----------

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        last_ip TEXT,
        vendor TEXT,
        first_seen TEXT,
        last_seen TEXT,
        status TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT,
        ip TEXT,
        event TEXT,
        ts TEXT
    )
    """)
    conn.commit()
    return conn

DB_CONN = init_db()
DB_LOCK = threading.Lock()

def upsert_device(mac, ip, vendor):
    ts = now_iso()
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("SELECT mac, last_ip, status FROM devices WHERE mac=?", (mac,))
        row = c.fetchone()
        if row:
            # update last_seen and ip if changed
            c.execute("UPDATE devices SET last_ip=?, vendor=?, last_seen=?, status='online' WHERE mac=?",
                      (ip, vendor, ts, mac))
            if row[1] != ip:
                log_event(mac, ip, "ip_changed", ts)
        else:
            c.execute("INSERT INTO devices(mac, last_ip, vendor, first_seen, last_seen, status) VALUES (?,?,?,?,?,?)",
                      (mac, ip, vendor, ts, ts, 'online'))
            log_event(mac, ip, "joined", ts)
        DB_CONN.commit()

def mark_all_offline():
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("UPDATE devices SET status='offline' WHERE status='online'")
        DB_CONN.commit()

def mark_offline_if_missing(current_macs):
    """
    current_macs: set of MACs seen this scan.
    Any device previously online but not in current_macs -> marked offline, event logged.
    """
    ts = now_iso()
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("SELECT mac, last_ip, status FROM devices WHERE status='online'")
        rows = c.fetchall()
        for mac, ip, status in rows:
            if mac not in current_macs:
                c.execute("UPDATE devices SET status='offline' WHERE mac=?", (mac,))
                log_event(mac, ip, "left", ts)
        DB_CONN.commit()

def log_event(mac, ip, event, ts=None):
    if ts is None:
        ts = now_iso()
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("INSERT INTO events(mac, ip, event, ts) VALUES (?,?,?,?)", (mac, ip, event, ts))
        DB_CONN.commit()

def get_all_devices():
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("SELECT mac, last_ip, vendor, first_seen, last_seen, status FROM devices")
        rows = c.fetchall()
        return [{
            "mac": r[0], "ip": r[1], "vendor": r[2], "first_seen": r[3], "last_seen": r[4], "status": r[5]
        } for r in rows]

def get_recent_events(limit=100):
    with DB_LOCK:
        c = DB_CONN.cursor()
        c.execute("SELECT mac, ip, event, ts FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [{"mac": r[0], "ip": r[1], "event": r[2], "ts": r[3]} for r in c.fetchall()]

# ---------- ARP / scanning functions ----------

def parse_arp_table():
    """Parse OS ARP table and return list of (ip, mac) tuples."""
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
            # lines:  192.168.1.1          00-11-22-33-44-55   dynamic
            import re
            res = []
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').lower()
                    res.append((ip, mac))
            return res
        else:
            # try `ip neigh`
            try:
                out = subprocess.check_output(["ip", "neigh"], universal_newlines=True)
                # lines: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                import re
                res = []
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        res.append((ip, mac))
                return res
            except Exception:
                # fallback to arp -a
                out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
                res = []
                import re
                for line in out.splitlines():
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{1,17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        res.append((ip, mac))
                return res
    except Exception:
        return []

def ping_host(ip):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT), ip]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT/1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int((PING_TIMEOUT+999)//1000)), ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
        return True
    except Exception:
        return False

def populate_arp_by_ping(ip_list, max_workers=100):
    # simple threaded pings
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ip_list) or 1)) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
                results.append((ip, ok))
            except Exception:
                results.append((ip, False))
    return results

def scapy_arp_scan(network_cidr, timeout=2):
    """Use scapy arping to return list of (ip, mac)."""
    if not SCAPY:
        return []
    try:
        conf.verb = 0
        ans, _ = arping(str(network_cidr), timeout=timeout)
        res = []
        for snd, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.lower()
            res.append((ip, mac))
        return res
    except Exception as e:
        debug_log(f"scapy arping error: {e}")
        return []

# ---------- High level scanner thread ----------

class ScannerThread(threading.Thread):
    def __init__(self, interval=SCAN_INTERVAL):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop = threading.Event()
        self.current_seen = set()

    def stop(self):
        self._stop.set()

    def run(self):
        debug_log("Scanner thread started.")
        while not self._stop.is_set():
            try:
                if not OUI_MAP:
                    # try to load or download OUI map if empty
                    if download_oui():
                        global OUI_MAP
                        OUI_MAP = load_oui_map()
                if psutil:
                    if_name, ip, mask = detect_primary_interface()
                else:
                    if_name, ip, mask = detect_primary_interface()
                if not ip:
                    debug_log("No interface IP detected; sleeping.")
                    time.sleep(self.interval)
                    continue

                # build network
                try:
                    if isinstance(mask, str) and mask.isdigit():
                        # mask may be CIDR length '24'
                        cidr = int(mask)
                        network_cidr = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
                    else:
                        # mask might be like 255.255.255.0
                        if mask and "." in str(mask):
                            cidr = sum(bin(int(x)).count('1') for x in mask.split('.'))
                            network_cidr = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
                        else:
                            network_cidr = ipaddress.ip_network(ip + "/24", strict=False)
                except Exception:
                    network_cidr = ipaddress.ip_network(ip + "/24", strict=False)

                debug_log(f"Scanning network {network_cidr} on interface {if_name}")

                # prefer scapy
                results = []
                if SCAPY:
                    results = scapy_arp_scan(network_cidr)
                if not results:
                    # fallback: limited ping sweep
                    hosts = list(network_cidr.hosts())
                    if len(hosts) > MAX_HOSTS_SCAN:
                        debug_log(f"Large subnet: limiting hosts to first {MAX_HOSTS_SCAN}")
                        hosts = hosts[:MAX_HOSTS_SCAN]
                    ips = [str(h) for h in hosts]
                    populate_arp_by_ping(ips)
                    entries = parse_arp_table()
                    # filter to ips we attempted
                    results = [(ip, mac) for ip, mac in entries if ip in set(ips)]
                # normalize and upsert
                seen_macs = set()
                for ip_addr, mac in results:
                    if not mac or mac.startswith("ff:ff:ff"):
                        continue
                    vendor = mac_to_vendor(mac)
                    upsert_device(mac, ip_addr, vendor)
                    seen_macs.add(mac)

                # mark offline for missing
                mark_offline_if_missing(seen_macs)

            except Exception as e:
                debug_log(f"Scanner exception: {e}")
            # sleep
            time.sleep(self.interval)

# ---------- Flask web app (dashboard) ----------

FLASK_APP = None
def create_app():
    if Flask is None:
        raise RuntimeError("Flask is not installed.")
    app = Flask(__name__, static_folder=None)

    @app.route("/api/devices")
    def api_devices():
        return jsonify(get_all_devices())

    @app.route("/api/events")
    def api_events():
        limit = int(request.args.get("limit", 200))
        return jsonify(get_recent_events(limit))

    @app.route("/api/export/<fmt>")
    def api_export(fmt):
        devices = get_all_devices()
        if fmt == "json":
            return jsonify(devices)
        elif fmt == "csv":
            import io, csv
            si = io.StringIO()
            w = csv.writer(si)
            w.writerow(["ip", "mac", "vendor", "first_seen", "last_seen", "status"])
            for d in devices:
                w.writerow([d["ip"], d["mac"], d["vendor"], d["first_seen"], d["last_seen"], d["status"]])
            return app.response_class(si.getvalue(), mimetype="text/csv")
        elif fmt == "txt":
            s = "\n".join(f"{d['ip']} {d['mac']} {d['vendor']}" for d in devices)
            return app.response_class(s, mimetype="text/plain")
        else:
            abort(404)

    DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>LAN Dashboard</title>
  <script src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
  <link href="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
  <style>
    body{font-family: Arial, Helvetica, sans-serif; margin:0; padding:0}
    #topbar{padding:8px;background:#222;color:#fff;display:flex;align-items:center;gap:10px}
    #graph{height:450px;border:1px solid #ddd}
    #list{height:300px;overflow:auto;padding:8px}
    button{padding:6px 10px}
    .badge-online{color:green;font-weight:bold}
    .badge-off{color:#888}
  </style>
</head>
<body>
  <div id="topbar">
    <div style="font-weight:700">LAN Dashboard</div>
    <button onclick="refresh()">Refresh</button>
    <button onclick="exportCSV()">Export CSV</button>
    <button onclick="exportJSON()">Export JSON</button>
    <div style="margin-left:auto">Updated: <span id="ts">-</span></div>
  </div>
  <div id="graph"></div>
  <div id="list"></div>

<script>
async function fetchJSON(url){const r=await fetch(url); return r.json();}
let nodes = new vis.DataSet();
let edges = new vis.DataSet();
let network = null;

function buildGraph(devices){
  nodes.clear(); edges.clear();
  // add gateway node (local device)
  nodes.add({id:'gw', label:'Gateway', color:'#f39c12'});
  devices.forEach(d=>{
    const label = d.ip + "\\n" + d.mac + "\\n" + d.vendor;
    nodes.add({id:d.mac, label:label, title:label, color: d.status=='online' ? '#7BE141' : '#CCCCCC'});
    edges.add({from:'gw', to:d.mac});
  });
  const container = document.getElementById('graph');
  const data = {nodes, edges};
  const options = {physics:{stabilization:false}, nodes:{shape:'box'}};
  if(!network){
    network = new vis.Network(container, data, options);
  } else {
    network.setData(data);
  }
}

async function refresh(){
  try{
    const devs = await fetchJSON('/api/devices');
    buildGraph(devs);
    const list = document.getElementById('list');
    list.innerHTML = '';
    devs.forEach(d=>{
      const el = document.createElement('div');
      el.innerHTML = `<b>${d.ip}</b> &nbsp; <span>${d.mac}</span> &nbsp; <span>${d.vendor}</span> &nbsp; <span class="${d.status=='online'?'badge-online':'badge-off'}">${d.status}</span>
      <div style="font-size:11px;color:#666">first:${d.first_seen} last:${d.last_seen}</div>`;
      list.appendChild(el);
    });
    document.getElementById('ts').innerText = new Date().toLocaleString();
  }catch(e){
    console.error(e);
  }
}

async function exportCSV(){
  window.location = '/api/export/csv';
}
async function exportJSON(){
  window.location = '/api/export/json';
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
    """

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    return app

# ---------- CLI helpers ----------

def export_logged(fmt, path):
    devices = get_all_devices()
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2)
    elif fmt == "csv":
        import csv
        with open(path, "w", newline='', encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "mac", "vendor", "first_seen", "last_seen", "status"])
            for d in devices:
                w.writerow([d['ip'], d['mac'], d['vendor'], d['first_seen'], d['last_seen'], d['status']])
    elif fmt == "txt":
        with open(path, "w", encoding="utf-8") as f:
            for d in devices:
                f.write(f"{d['ip']} {d['mac']} {d['vendor']} {d['status']}\n")
    debug_log(f"Exported {len(devices)} devices to {path}")

# ---------- Entrypoint & arg parsing ----------

def main():
    p = ArgumentParser()
    p.add_argument("--serve", action="store_true", help="Start Flask web dashboard + scanner")
    p.add_argument("--scan-only", action="store_true", help="Run scanner only (no web server)")
    p.add_argument("--gui", action="store_true", help="Open dashboard in browser (starts server if needed)")
    p.add_argument("--export", nargs=2, metavar=("fmt","path"), help="Export logged devices (fmt: json|csv|txt) to path")
    p.add_argument("--update-oui", action="store_true", help="Force download/update OUI database")
    p.add_argument("--interval", type=int, default=SCAN_INTERVAL, help="Scanner interval seconds")
    args = p.parse_args()

    if args.update_oui:
        ok = download_oui(force=True)
        if ok:
            debug_log("Updated OUI DB.")
        else:
            debug_log("Failed to update OUI DB.")
        # continue to other operations

    # load oui map
    global OUI_MAP
    OUI_MAP = load_oui_map()

    # start scanner thread
    scanner = ScannerThread(interval=args.interval)
    scanner.start()

    if args.export:
        fmt, path = args.export
        export_logged(fmt.lower(), path)
        # stop scanner and exit
        scanner.stop()
        return

    if args.scan_only:
        debug_log("Running scanner only. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            debug_log("Stopping scanner...")
            scanner.stop()
            time.sleep(0.5)
        return

    if args.serve or args.gui:
        if Flask is None:
            print("Flask is required for --serve/--gui. Install with: pip install flask")
            scanner.stop()
            return
        app = create_app()
        # run in thread to keep CLI responsive
        def run_flask():
            debug_log("Starting Flask server at http://127.0.0.1:5000 ...")
            app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

        t = threading.Thread(target=run_flask, daemon=True)
        t.start()
        time.sleep(0.5)
        if args.gui:
            # open browser
            import webbrowser
            webbrowser.open("http://127.0.0.1:5000")
        # keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            debug_log("Shutting down...")
            scanner.stop()
            time.sleep(0.5)
            return

    # default: show help
    p.print_help()
    scanner.stop()

if __name__ == "__main__":
    main()
