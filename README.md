# Advanced Packet Sniffer

## Overview
Advanced Packet Sniffer is a Python-based network traffic monitoring tool with a graphical user interface (GUI) built using Tkinter. It allows users to capture network packets in real-time, apply filters, and save the captured data in a PCAP file format.

## Features
- **Real-time Packet Capture**: Monitor live network traffic.
- **Protocol Filtering**: Filter packets by TCP, UDP, ICMP, ARP, DNS, or HTTP.
- **User-Friendly Interface**: Intuitive GUI with start, stop, and save functionality.
- **Auto-Scrolling Log**: View captured packets in real-time.
- **PCAP File Saving**: Save captured packets for later analysis.

## Prerequisites
Ensure you have the following installed on your system:
- Python 3.x
- Required dependencies:
  pip3 install scapy
  (Tkinter is included by default in most Python installations.)

## Installation
1. Clone the repository or download the script
   git clone https://github.com/yourusername/AdvancedPacketSniffer.git
   cd AdvancedPacketSniffer

2. Run the script:
   python3 sniffer.py


## Usage
1. Open the application.
2. Select a filter from the dropdown menu (or use "All" for capturing all traffic).
3. Click **Start Sniffing** to begin capturing packets.
4. Click **Stop Sniffing** to stop capturing.
5. Click **Save Packets** to store the captured data as a `.pcap` file.

## Notes
- Running the script requires administrative privileges (root access) for packet sniffing.
- Some packets might be dropped due to OS-level restrictions.
- The "Stop Sniffing" button will not immediately halt ongoing packet capture since Scapy does not provide built-in stop functionality.

## License
This project is licensed under the MIT License.

## Author
Developed by Itqa Akhlaq
