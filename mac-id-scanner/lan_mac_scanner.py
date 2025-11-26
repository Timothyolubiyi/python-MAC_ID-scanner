#!/usr/bin/env python3
"""
LAN MAC Scanner
- Attempts to discover devices on the local LAN and print IP -> MAC addresses.
- Uses scapy.arping() if scapy is available and script is run with privileges.
- Otherwise performs a ping sweep to populate OS ARP table then parses `arp -a`.

Usage:
    python3 lan_mac_scanner.py
"""

import sys
import os
import subprocess
import re
import socket
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional scapy import
try:
    from scapy.all import arping, conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def get_local_ip():
    """Get the primary local IP by opening a UDP socket (no packets sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't actually send packets
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # fallback
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def guess_network(local_ip):
    """Try to guess the network. Prefer system info later; default to /24."""
    if local_ip is None:
        return None
    # Default network /24
    return ipaddress.ip_network(local_ip + '/24', strict=False)

def ping(ip_str, timeout=1000):
    """
    Ping a single IP. Cross-platform. Return True if ping command succeeded (host reachable).
    timeout in milliseconds (Windows uses -w, Unix uses -W in seconds).
    """
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout), ip_str]
    elif system == "Darwin":  # macOS
        # macOS ping uses -W in milliseconds? easier to use -c 1 and rely on default timeout
        cmd = ["ping", "-c", "1", "-W", str(int(timeout/1000)), ip_str]
    else:  # Linux and others
        # On many Linuxes -c 1 -W <timeout_seconds>
        cmd = ["ping", "-c", "1", "-W", str(int((timeout+999)//1000)), ip_str]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        # ping not present; treat as unreachable
        return False

def populate_arp_table(network, max_workers=100):
    """Ping every host in network (except network/broadcast) concurrently to populate ARP table."""
    ips = [str(ip) for ip in network.hosts()]
    # Limit tasks if very large network
    if len(ips) > 1024:
        ips = ips[:1024]  # safety: scan first 1024 hosts if huge
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        futures = {ex.submit(ping, ip): ip for ip in ips}
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
            # parse lines like:  192.168.1.1          00-11-22-33-44-55   dynamic
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17}|[0-9a-fA-F-]{14})", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').lower()
                    entries.append((ip, mac))
        else:
            # Try "ip neigh" first (Linux)
            try:
                out = subprocess.check_output(["ip", "neigh"], universal_newlines=True)
                # lines like: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        entries.append((ip, mac))
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to arp -a (macOS or systems w/o ip)
                out = subprocess.check_output(["arp", "-a"], universal_newlines=True)
                # macOS: ? (192.168.1.10) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
                for line in out.splitlines():
                    m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+.*\s+at\s+([0-9a-fA-F:]{17}|[0-9a-fA-F:]{1,17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        entries.append((ip, mac))
    except Exception:
        pass

    # Deduplicate and clean
    seen = {}
    for ip, mac in entries:
        if mac in ("<incomplete>", "ff:ff:ff:ff:ff:ff"):
            continue
        seen[ip] = mac
    return list(seen.items())

def scapy_scan(network, timeout=2):
    """Perform ARP scan with scapy. Returns list of (ip, mac)."""
    # scapy's arping returns (answered, unanswered)
    # Make sure scapy doesn't try to use verbose output
    conf.verb = 0
    try:
        answered, _ = arping(str(network), timeout=timeout)
    except Exception as e:
        return []
    results = []
    for snd, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        results.append((ip, mac))
    return results

def main():
    print("LAN MAC Scanner\n----------------\n")
    local_ip = get_local_ip()
    if not local_ip:
        print("⚠️ Could not determine local IP address. Exiting.")
        sys.exit(1)
    print(f"Local IP detected: {local_ip}")

    network = guess_network(local_ip)
    if network is None:
        print("⚠️ Could not determine network. Exiting.")
        sys.exit(1)
    print(f"Scanning network: {network} (note: scanning may be limited to first 1024 hosts on very large networks)\n")

    # Prefer scapy if available and running as root/admin
    use_scapy = SCAPY_AVAILABLE and (os.geteuid() == 0 if hasattr(os, "geteuid") else ctypes_getwindows_admin())
    if SCAPY_AVAILABLE:
        print("scapy is available.")
    else:
        print("scapy not available; falling back to ping+arp parsing method.")

    if SCAPY_AVAILABLE:
        try:
            # On Windows, scapy can run without geteuid; skip admin check but user should run as admin
            print("Attempting scapy ARP scan (needs root/admin privileges)...")
            results = scapy_scan(network)
            if results:
                print_results(results)
                return
            else:
                print("Scapy scan returned no results or not permitted; falling back to ping+arp parsing.")
        except Exception as e:
            print(f"Scapy scan error: {e}\nFalling back to ping+arp parsing.")

    # Ping sweep to populate ARP entries
    print("Pinging hosts to populate ARP table (this may take a while)...")
    populate_arp_table(network)

    # Parse ARP table
    arp_entries = parse_arp_table()
    if not arp_entries:
        print("No ARP entries found. Either there are no active hosts that responded or arp/ping is restricted.")
    else:
        print_results(arp_entries)

def ctypes_getwindows_admin():
    """Return True if running with admin on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def print_results(results):
    """Print IP -> MAC table sorted by IP."""
    try:
        # Sort by IP address
        results_sorted = sorted(results, key=lambda x: ipaddress.ip_address(x[0]))
    except Exception:
        results_sorted = results

    print("\nDiscovered devices (IP -> MAC):")
    print("{:<16}  {}".format("IP", "MAC"))
    print("-" * 32)
    for ip, mac in results_sorted:
        print(f"{ip:<16}  {mac}")
    print(f"\nTotal found: {len(results_sorted)}")

if __name__ == "__main__":
    main()
