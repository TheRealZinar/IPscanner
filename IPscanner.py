import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import socket

def get_mac_and_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname

def scan_network(network_range="192.168.0.1/24"):
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_mac_and_hostname(ip)
        devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": "N/A"})  # Placeholder for vendor
    return devices

def start_scan():
    # Clear previous results
    for item in tree.get_children():
        tree.delete(item)

    network_range = "192.168.0.1/24"
    devices = scan_network(network_range)

    # Insert results into the table
    for device in devices:
        tree.insert("", "end", values=(device["hostname"], device["ip"], device["vendor"], device["mac"]))

# Create the main window
root = tk.Tk()
root.title("Network IP Scanner")
root.geometry("600x400")

# Create a frame for the scan button
frame_top = tk.Frame(root)
frame_top.pack(pady=10)

# Scan button
scan_button = tk.Button(frame_top, text="Scan 192.168.0.1 - 192.168.0.254", command=start_scan)
scan_button.grid(row=0, column=0, padx=5)

# Create a treeview for the results
columns = ("Name", "IP", "Vendor", "MAC Address")
tree = ttk.Treeview(root, columns=columns, show="headings")
tree.heading("Name", text="Name")
tree.heading("IP", text="IP")
tree.heading("Vendor", text="Vendor")
tree.heading("MAC Address", text="MAC Address")

# Configure column widths
tree.column("Name", width=150)
tree.column("IP", width=100)
tree.column("Vendor", width=150)
tree.column("MAC Address", width=150)

tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Run the GUI event loop
root.mainloop()
