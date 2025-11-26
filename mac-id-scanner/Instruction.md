Quick notes and tips

If you want a faster and more reliable scan, install Scapy and run the script as root / Administrator:

pip install scapy

Linux/macOS: sudo python3 lan_mac_scanner.py

Windows: Run CMD/PowerShell as Administrator then python lan_mac_scanner.py

If your laptop has multiple network interfaces (Wi-Fi + Ethernet + VPN), the script picks the interface used for outbound traffic. For more advanced control you can extend the script to let you pick an interface and netmask explicitly.

