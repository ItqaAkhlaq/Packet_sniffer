import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import threading
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw

# Global variables
captured_packets = []
sniffing = False  # Flag to control sniffing

# Function to update the GUI with captured packets
def packet_callback(packet):
    try:
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "ARP" if packet.haslayer(ARP) else "DNS" if packet.haslayer(DNS) else "Other"
        length = len(packet)
        
        # Display packet details in GUI
        packet_summary = f"[{proto}] {src_ip} -> {dst_ip} | Length: {length} bytes"
        text_area.insert(tk.END, packet_summary + "\n")
        text_area.yview(tk.END)  # Auto-scroll to the latest packet
        
        captured_packets.append(packet)  # Store packet for saving

    except Exception as e:
        text_area.insert(tk.END, f"[Error] {str(e)}\n")

# Function to start sniffing in a separate thread
def start_sniffing():
    global sniffing
    sniffing = True
    text_area.insert(tk.END, "[*] Sniffing started...\n")
    
    # Get selected filter from dropdown
    selected_filter = filter_var.get()
    bpf_filter = ""

    if selected_filter == "TCP":
        bpf_filter = "tcp"
    elif selected_filter == "UDP":
        bpf_filter = "udp"
    elif selected_filter == "ICMP":
        bpf_filter = "icmp"
    elif selected_filter == "ARP":
        bpf_filter = "arp"
    elif selected_filter == "DNS":
        bpf_filter = "udp port 53"
    elif selected_filter == "HTTP":
        bpf_filter = "tcp port 80 or tcp port 443"

    # Start sniffing in a thread to prevent GUI from freezing
    thread = threading.Thread(target=lambda: sniff(filter=bpf_filter, prn=packet_callback, store=0))
    thread.daemon = True
    thread.start()

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    text_area.insert(tk.END, "[*] Sniffing stopped.\n")

# Function to save captured packets to a .pcap file
def save_packets():
    if not captured_packets:
        text_area.insert(tk.END, "[!] No packets to save.\n")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                             filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        wrpcap(file_path, captured_packets)
        text_area.insert(tk.END, f"[*] Packets saved to {file_path}\n")

# Create GUI window
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("900x500")

# Label
label = tk.Label(root, text="Network Packet Sniffer", font=("Arial", 14))
label.pack(pady=5)

# Dropdown for selecting packet filter
filter_var = tk.StringVar(value="All")
filter_label = tk.Label(root, text="Filter: ")
filter_label.pack(pady=2)
filter_dropdown = ttk.Combobox(root, textvariable=filter_var, values=["All", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"])
filter_dropdown.pack(pady=2)

# Scrollable text area for packet display
text_area = scrolledtext.ScrolledText(root, width=100, height=20)
text_area.pack(pady=5)

# Button Frame
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Buttons
start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white")
stop_button.grid(row=0, column=1, padx=5)

save_button = tk.Button(button_frame, text="Save Packets", command=save_packets, bg="blue", fg="white")
save_button.grid(row=0, column=2, padx=5)

# Run the GUI
root.mainloop()
