import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP, Raw, srp
import threading
import keyboard
import time
import subprocess
import re

sniffer_running = False
sniffer_thread = None
keylogger_running = False
keylogger_thread = None
scanner_running = False
scanner_thread = None

def key_logger():
    global keylogger_running, keylogger_thread
    if keylogger_running:
        keylogger_running = False
        update_output("\n[*] Keylogger stopped.")
    else:
        keylogger_running = True
        update_output("\n[*] Keylogger started.")
        keylogger_thread = threading.Thread(target=start_keylogger, daemon=True)
        keylogger_thread.start()

def start_keylogger():
    def on_press(event):
        if not keylogger_running:
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        update_output(f"[{timestamp}] -> {event.name}")
    
    keyboard.on_press(on_press)
    keyboard.wait()

def network_scanner():
    global scanner_running, scanner_thread
    if scanner_running:
        scanner_running = False
        update_output("\n[*] Network Scanner stopped.")
    else:
        target_ip = simpledialog.askstring("Network Scanner", "Enter target IP range (e.g., 192.168.1.0/24):")
        if target_ip:
            scanner_running = True
            update_output(f"\n[*] Scanning network {target_ip}...")
            scanner_thread = threading.Thread(target=start_network_scanner, args=(target_ip,), daemon=True)
            scanner_thread.start()

def start_network_scanner(target_ip):
    global scanner_running
    arp_request = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    update_output("\n[*] Available devices in the network:")
    update_output("IP Address\t\tMAC Address")
    update_output("-----------------------------------------")
    for device in devices:
        update_output(f"{device['ip']}\t\t{device['mac']}")
    
    scanner_running = False

def packet_analyzer():
    global sniffer_running, sniffer_thread
    if sniffer_running:
        sniffer_running = False
        update_output("\n[*] Packet Sniffer stopped.")
    else:
        sniffer_running = True
        update_output("\n[*] Packet Sniffer started.")
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()

def mac_changer():
    interface = simpledialog.askstring("MAC Changer", "Enter network interface (e.g., eth0, wlan0):")
    new_mac = simpledialog.askstring("MAC Changer", "Enter new MAC address (e.g., 00:11:22:33:44:55):")
    
    if interface and new_mac:
        current_mac = get_current_mac(interface)
        update_output(f"[*] Current MAC: {current_mac}")
        change_mac(interface, new_mac)
        updated_mac = get_current_mac(interface)
        if updated_mac == new_mac:
            update_output(f"[+] MAC address successfully changed to {updated_mac}")
        else:
            update_output("[-] MAC address change failed.")

def change_mac(interface, new_mac):
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])

def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode()
        mac_address_search_result = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", ifconfig_result)
        return mac_address_search_result.group(0) if mac_address_search_result else "Unknown"
    except:
        return "Unknown"

def update_output(text):
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)
    output_text.config(state=tk.DISABLED)

def clear_output():
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)

def packet_callback(packet):
    if not sniffer_running:
        return
    output = "\n[+] New Packet Captured:"
    if Ether in packet:
        output += f"\n[+] Ethernet Frame:\n    Source MAC: {packet[Ether].src}\n    Destination MAC: {packet[Ether].dst}"
    if IP in packet:
        output += f"\n[+] IP Packet:\n    Source IP: {packet[IP].src}\n    Destination IP: {packet[IP].dst}\n    Protocol: {packet[IP].proto}"
    if TCP in packet:
        output += f"\n[+] TCP Segment:\n    Source Port: {packet[TCP].sport}\n    Destination Port: {packet[TCP].dport}\n    Flags: {packet[TCP].flags}"
    if UDP in packet:
        output += f"\n[+] UDP Datagram:\n    Source Port: {packet[UDP].sport}\n    Destination Port: {packet[UDP].dport}"
    if ARP in packet:
        output += f"\n[+] ARP Packet:\n    Operation: {packet[ARP].op}\n    Sender MAC: {packet[ARP].hwsrc}\n    Sender IP: {packet[ARP].psrc}\n    Target MAC: {packet[ARP].hwdst}\n    Target IP: {packet[ARP].pdst}"
    if ICMP in packet:
        output += f"\n[+] ICMP Packet:\n    Type: {packet[ICMP].type}\n    Code: {packet[ICMP].code}"
    if Raw in packet:
        output += f"\n[+] Raw Payload:\n    Payload: {packet[Raw].load}"
    update_output(output)

def start_sniffer():
    global sniffer_running
    sniff(prn=packet_callback, store=False)
    sniffer_running = False

root = tk.Tk()
root.title("StrikeNet")
root.geometry("500x500")
root.configure(bg="#1E1E1E")

tk.Label(root, text="🔒 StrikeNet", font=("Arial", 16, "bold"), fg="white", bg="#1E1E1E").pack(pady=10)

buttons = [
    ("📝 Key Logger", key_logger, "#3B82F6"),
    ("🌐 Network Scanner", network_scanner, "#10B981"),
    ("📡 Packet Sniffer", packet_analyzer, "#F59E0B"),
    ("🔄 Mac Changer", mac_changer, "#EF4444")
]

for text, command, color in buttons:
    tk.Button(root, text=text, command=command, font=("Arial", 12), bg=color, fg="white", 
              activebackground="#374151", relief="flat", padx=10, pady=5, width=25).pack(pady=5)

output_text = scrolledtext.ScrolledText(root, height=10, width=60, bg="#1E1E1E", fg="white", state=tk.DISABLED)
output_text.pack(pady=10)

root.mainloop()
