#!/usr/bin/env python3
"""
LAN MAC Scanner — Full edition
Features:
 - CLI and GUI (Tkinter)
 - Scapy ARP scan (if scapy available and permitted)
 - Fallback: ping sweep to populate ARP table, then parse ARP table
 - Export to JSON or CSV
 - Accepts explicit IP range/network or IP start-end
 - Optionally choose a network interface (best-effort)
"""

import sys
import os
import subprocess
import re
import socket
import platform
import ipaddress
import argparse
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Optional GUI import (Tkinter is in stdlib)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# Optional scapy import
try:
    from scapy.all import arping, conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Optional psutil import for interface enumeration
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

# ---------- Utility functions ----------

def get_local_ip():
    """Get the primary local IP by opening a UDP socket (doesn't send packets)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def enumerate_interfaces():
    """Return list of (name, ip) tuples if possible."""
    result = []
    if PSUTIL_AVAILABLE:
        try:
            addrs = psutil.net_if_addrs()
            for ifname, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        result.append((ifname, addr.address))
            # Also include primary detected IP if not present
            primary = get_local_ip()
            if primary and not any(ip == primary for (_, ip) in result):
                result.insert(0, ("detected", primary))
        except Exception:
            pass
    else:
        primary = get_local_ip()
        if primary:
            result.append(("detected", primary))
    return result

def parse_range(range_str, fallback_network=None):
    """
    Accepts:
     - CIDR: 192.168.1.0/24
     - Single IP: 192.168.1.10
     - Start-End: 192.168.1.10-192.168.1.50
    Returns ipaddress.IPv4Network or list of IP strings (for start-end)
    """
    if not range_str:
        return fallback_network
    range_str = range_str.strip()
    # CIDR or single IP
    try:
        if '/' in range_str:
            net = ipaddress.ip_network(range_str, strict=False)
            return net
        else:
            if '-' in range_str:
                start, end = range_str.split('-', 1)
                # ensure both are IPs
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                # create list of IP strings inclusive
                ips = []
                cur = int(start_ip)
                while cur <= int(end_ip):
                    ips.append(str(ipaddress.ip_address(cur)))
                    cur += 1
                return ips
            else:
                # single IP -> treat as /32 network
                ip = ipaddress.ip_address(range_str)
                return ipaddress.ip_network(str(ip) + '/32', strict=False)
    except Exception as e:
        raise ValueError(f"Invalid range format: {e}")

def guess_network_from_ip(ip_str):
    """Guess network using /24 if no better info."""
    if not ip_str:
        return None
    try:
        return ipaddress.ip_network(ip_str + '/24', strict=False)
    except Exception:
        return None

# ---------- Scanning methods ----------

def scapy_scan(network, timeout=2):
    """Perform ARP scan with scapy. Returns list of (ip, mac)."""
    conf.verb = 0
    results = []
    try:
        answered, _ = arping(str(network), timeout=timeout)
    except Exception:
        return []
    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        results.append((ip, mac.lower()))
    return results

def ping(ip_str, timeout=1000):
    """
    Ping a single IP. Cross-platform. Return True if ping command succeeded (host reachable).
    timeout in milliseconds for Windows, seconds for others converted appropriately.
    """
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout), ip_str]
    elif system == "Darwin":  # macOS
        # macOS ping uses -W in milliseconds only on some versions; fallback to -c 1
        cmd = ["ping", "-c", "1", "-W", str(int(timeout/1000)), ip_str]
    else:
        # Linux: -c 1, -W timeout in seconds (integer)
        cmd = ["ping", "-c", "1", "-W", str(int((timeout+999)//1000)), ip_str]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def populate_arp_table_for_ips(ip_list, max_workers=100):
    """Ping each IP concurrently (to populate ARP table)."""
    if not ip_list:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ip_list))) as ex:
        futures = {ex.submit(ping, ip): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
                results.append((ip, ok))
            except Exception:
                results.append((ip, False))
    return results

def parse_arp_table():
    """Parse OS ARP table (arp -a or ip neigh) and return list of (ip, mac)."""
    system = platform.system()
    entries = []
    try:
        if system == "Windows":
            out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17}|[0-9a-fA-F-]{14})", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').lower()
                    entries.append((ip, mac))
        else:
            # Try ip neigh on Linux
            try:
                out = subprocess.check_output(["ip", "neigh"], universal_newlines=True)
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        entries.append((ip, mac))
            except (subprocess.CalledProcessError, FileNotFoundError):
                out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
                for line in out.splitlines():
                    # macOS and other arp formats
                    m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+.*\s+at\s+([0-9a-fA-F:]{1,17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        entries.append((ip, mac))
    except Exception:
        pass
    # Deduplicate keeping last seen
    seen = {}
    for ip, mac in entries:
        if mac in ("<incomplete>", "ff:ff:ff:ff:ff:ff"):
            continue
        seen[ip] = mac
    return list(seen.items())

# ---------- High-level scanner ----------

def scan_network(range_or_net=None, interface=None, prefer_scapy=True, max_hosts_limit=1024):
    """
    range_or_net: ipaddress.IPv4Network or list of ip strings or None (auto-detect)
    interface: not currently used to bind scapy; it's informational / for UI
    prefer_scapy: use scapy if available
    """
    local_ip = get_local_ip()
    if not local_ip and range_or_net is None:
        raise RuntimeError("Cannot determine local IP and no range was provided.")

    # Decide network to scan
    if range_or_net is None:
        net = guess_network_from_ip(local_ip)
    else:
        net = range_or_net

    results = []

    # If scapy available and preferred, try it first
    use_scapy = SCAPY_AVAILABLE and prefer_scapy
    if use_scapy:
        try:
            # scapy arping accepts networks or IP ranges
            print("Attempting scapy ARP scan (recommended; requires root/admin).")
            scapy_results = scapy_scan(net)
            if scapy_results:
                # normalize macs
                return sorted(list({ip: mac for ip, mac in scapy_results}.items()), key=lambda x: ipaddress.ip_address(x[0]))
            else:
                print("Scapy scan returned no results or not permitted. Falling back.")
        except Exception as e:
            print(f"Scapy scan error: {e}. Falling back to ping+arp.")

    # Fallback method: ping sweep and parse arp
    print("Using ping sweep + ARP table parsing (fallback). This may take a while for large ranges.")
    ip_list = []
    if isinstance(net, list):
        ip_list = net
    elif isinstance(net, ipaddress._BaseNetwork):
        # build host list but cap
        hosts = list(net.hosts())
        if len(hosts) > max_hosts_limit:
            print(f"Network has {len(hosts)} hosts; limiting to first {max_hosts_limit} hosts for safety.")
            hosts = hosts[:max_hosts_limit]
        ip_list = [str(h) for h in hosts]
    else:
        # single IP network
        try:
            ip_list = [str(ip) for ip in net.hosts()]
        except Exception:
            ip_list = [str(net)]

    # Ping to populate ARP table
    populate_arp_table_for_ips(ip_list)

    # Now parse ARP table
    arp_entries = parse_arp_table()
    # Filter to only those in our ip_list if ip_list was limited
    if ip_list:
        arp_filtered = [(ip, mac) for ip, mac in arp_entries if ip in set(ip_list)]
    else:
        arp_filtered = arp_entries

    # Sort and return unique by IP
    seen = {}
    for ip, mac in arp_filtered:
        seen[ip] = mac
    results = sorted(list(seen.items()), key=lambda x: ipaddress.ip_address(x[0]))
    return results

# ---------- Export helpers ----------

def export_json(results, outfile):
    data = [{"ip": ip, "mac": mac} for ip, mac in results]
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump({"scanned_at": datetime.utcnow().isoformat() + "Z", "results": data}, f, indent=2)
    print(f"Exported {len(results)} entries to JSON: {outfile}")

def export_csv(results, outfile):
    with open(outfile, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "mac"])
        for ip, mac in results:
            writer.writerow([ip, mac])
    print(f"Exported {len(results)} entries to CSV: {outfile}")

# ---------- CLI and argument parsing ----------

def cli_main(args):
    # Determine range
    fallback_net = None
    local_ip = get_local_ip()
    if local_ip:
        fallback_net = guess_network_from_ip(local_ip)

    try:
        range_parsed = parse_range(args.range, fallback_network=fallback_net) if args.range else fallback_net
    except ValueError as e:
        print(f"Error parsing range: {e}")
        sys.exit(1)

    # If user requested interface, attempt to validate
    if args.interface:
        interfaces = enumerate_interfaces()
        if interfaces:
            if not any(args.interface == name or args.interface == ip for (name, ip) in interfaces):
                print(f"Warning: interface '{args.interface}' not found among detected interfaces: {interfaces}")

    try:
        results = scan_network(range_parsed, interface=args.interface, prefer_scapy=not args.no_scapy, max_hosts_limit=args.max_hosts)
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)

    if not results:
        print("No devices discovered.")
    else:
        print("\nDiscovered devices (IP -> MAC):")
        print("{:<16}  {}".format("IP", "MAC"))
        print("-" * 36)
        for ip, mac in results:
            print(f"{ip:<16}  {mac}")
        print(f"\nTotal found: {len(results)}")

    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)

# ---------- Simple GUI ----------

class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN MAC Scanner")
        self.geometry("800x500")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Top frame for options
        opt_frame = ttk.Frame(self, padding=8)
        opt_frame.pack(fill="x")

        ttk.Label(opt_frame, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar()
        iface_combo = ttk.Combobox(opt_frame, textvariable=self.iface_var, width=30)
        iface_combo.grid(row=0, column=1, sticky="w", padx=4)
        ifaces = enumerate_interfaces()
        iface_combo['values'] = [f"{n} ({ip})" for n, ip in ifaces] if ifaces else []
        if ifaces:
            iface_combo.current(0)

        ttk.Label(opt_frame, text="Range (CIDR or start-end):").grid(row=1, column=0, sticky="w", pady=4)
        self.range_var = tk.StringVar()
        ttk.Entry(opt_frame, textvariable=self.range_var, width=40).grid(row=1, column=1, sticky="w", padx=4)

        self.scan_btn = ttk.Button(opt_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, rowspan=2, padx=8)

        self.progress = ttk.Label(opt_frame, text="")
        self.progress.grid(row=2, column=0, columnspan=3, sticky="w", pady=4)

        # Treeview for results
        self.tree = ttk.Treeview(self, columns=("ip", "mac"), show="headings")
        self.tree.heading("ip", text="IP")
        self.tree.heading("mac", text="MAC")
        self.tree.column("ip", width=160)
        self.tree.column("mac", width=200)
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Bottom buttons
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Export JSON", command=self.export_json_gui).pack(side="left", padx=4)
        ttk.Button(bottom, text="Export CSV", command=self.export_csv_gui).pack(side="left", padx=4)
        ttk.Button(bottom, text="Clear", command=self.clear_results).pack(side="left", padx=4)
        ttk.Button(bottom, text="Quit", command=self.on_close).pack(side="right", padx=4)

        self.results = []

    def set_progress(self, text):
        self.progress.config(text=text)
        self.update_idletasks()

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results = []

    def start_scan(self):
        self.clear_results()
        rng = self.range_var.get().strip()
        iface = None
        if self.iface_var.get():
            # extract ip from displayed combo value
            selected = self.iface_var.get()
            m = re.search(r"\(([\d\.]+)\)$", selected)
            if m:
                iface = m.group(1)
            else:
                iface = selected.split()[0]

        self.set_progress("Parsing range...")
        try:
            fallback = guess_network_from_ip(get_local_ip())
            parsed = parse_range(rng, fallback_network=fallback) if rng else fallback
        except Exception as e:
            messagebox.showerror("Invalid range", str(e))
            return

        self.set_progress("Scanning... (this may take a while)")
        self.scan_btn.config(state="disabled")
        self.update_idletasks()
        # Run scan in background thread to keep UI responsive
        import threading
        t = threading.Thread(target=self._run_scan_thread, args=(parsed, iface), daemon=True)
        t.start()

    def _run_scan_thread(self, parsed, iface):
        try:
            results = scan_network(parsed, interface=iface)
            self.results = results
            self._populate_tree(results)
            self.set_progress(f"Scan complete: {len(results)} devices found.")
        except Exception as e:
            messagebox.showerror("Scan error", str(e))
            self.set_progress("Scan failed.")
        finally:
            self.scan_btn.config(state="normal")

    def _populate_tree(self, results):
        # populate Treeview in main thread
        def _insert():
            for ip, mac in results:
                self.tree.insert("", "end", values=(ip, mac))
        self.after(0, _insert)

    def export_json_gui(self):
        if not self.results:
            messagebox.showinfo("No data", "No scan results to export.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if f:
            export_json(self.results, f)
            messagebox.showinfo("Exported", f"Exported {len(self.results)} entries to {f}")

    def export_csv_gui(self):
        if not self.results:
            messagebox.showinfo("No data", "No scan results to export.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if f:
            export_csv(self.results, f)
            messagebox.showinfo("Exported", f"Exported {len(self.results)} entries to {f}")

    def on_close(self):
        self.destroy()

# ---------- Entrypoint ----------

def main():
    parser = argparse.ArgumentParser(description="LAN MAC Scanner — CLI + GUI")
    parser.add_argument("--range", "-r", help="IP range to scan (CIDR like 192.168.1.0/24 or start-end like 192.168.1.10-192.168.1.50)")
    parser.add_argument("--interface", "-i", help="Network interface name or IP (best-effort, informational)")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--gui", action="store_true", help="Open the Tkinter GUI")
    parser.add_argument("--no-scapy", action="store_true", help="Do not attempt to use scapy even if installed")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Max hosts to scan for large networks (default 1024)")
    args = parser.parse_args()

    if args.gui:
        if not GUI_AVAILABLE:
            print("GUI modules not available. Tkinter not found.")
            sys.exit(1)
        app = ScannerGUI()
        app.mainloop()
        return

    cli_main(args)

if __name__ == "__main__":
    main()
