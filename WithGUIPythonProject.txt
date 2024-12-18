import tkinter as tk
from tkinter import ttk, messagebox
import socket
import scapy.all as scapy
from colorama import Fore, Style
import json


# Function to scan multiple devices in a network
def scanMultiple(ip):
    arp_req_frame = scapy.ARP(pdst=ip)
    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[
        0
    ]
    result = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        result.append({"ip": ip, "mac": mac})
    return result


# Function to scan a single IP
def scanSingle(ip):
    arp_req_frame = scapy.ARP(pdst=ip)
    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[
        0
    ]
    result = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        hostname = "Unknown"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"
        result.append({"ip": ip, "mac": mac, "hostname": hostname})
    return result


# Function to scan ports
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


# Function to display results in a new window
def display_results(results, port_results=None):
    result_window = tk.Toplevel()
    result_window.title("Scan Results")
    result_window.geometry("600x400")
    text_area = tk.Text(result_window, wrap=tk.WORD)
    text_area.pack(fill=tk.BOTH, expand=True)

    if isinstance(results, list):  # Multiple results
        for device in results:
            text_area.insert(tk.END, f"IP: {device['ip']}, \nMAC: {device['mac']}\n")
    else:  # Single result
        text_area.insert(
            tk.END,
            f"IP: {results['ip']}, \nMAC: {results['mac']}, \nHostname: {results['hostname']}\n",
        )

    if port_results:
        text_area.insert(tk.END, "\nOpen Ports:\n")
        for port in port_results:
            text_area.insert(tk.END, f"Port: {port}\n")

    text_area.configure(state=tk.DISABLED)


# Main GUI Application
def main_gui():
    def scan_network():
        network = network_entry.get()
        if not network:
            messagebox.showerror("Error", "Please enter a network range!")
            return

        results = scanMultiple(network)
        if results:
            display_results(results)
            save_results(results)
        else:
            messagebox.showinfo("No Results", "No devices found.")

    def scan_single_ip():
        ip = ip_entry.get()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address!")
            return

        results = scanSingle(ip)
        if results:
            ports = [20, 21, 22, 23, 25, 80, 443, 8080]
            open_ports = []
            for device in results:
                open_ports += scan_ports(device["ip"], ports)
            display_results(results[0], open_ports)
            save_results(results)
        else:
            messagebox.showinfo("No Results", "No devices found.")

    def save_results(results, filename="scan_results.json"):
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        messagebox.showinfo("Saved", f"Results saved to {filename}")

    # Create main window
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("400x300")

    # Network range scanning section
    ttk.Label(root, text="Network Range (e.g., 192.168.1.0/24):").pack(pady=5)
    network_entry = ttk.Entry(root, width=40)
    network_entry.pack(pady=5)
    ttk.Button(root, text="Scan Network", command=scan_network).pack(pady=5)

    # Single IP scanning section
    ttk.Label(root, text="Single IP (e.g., 192.168.1.1):").pack(pady=5)
    ip_entry = ttk.Entry(root, width=40)
    ip_entry.pack(pady=5)
    ttk.Button(root, text="Scan Single IP", command=scan_single_ip).pack(pady=5)

    # Exit button
    ttk.Button(root, text="Exit", command=root.quit).pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main_gui()
