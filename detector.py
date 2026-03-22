import scapy.all as scapy

def sniff(interface):
    """Function to start sniffing on the specified network interface."""
    print(f"[*] Starting Packet Sniffer on {interface}...")
    # sniff function monitors the network and calls process_packet for each packet
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    """Function to analyze each captured packet for ARP responses."""
    # Check if the packet has an ARP layer
    if packet.haslayer(scapy.ARP):
        # op=2 means it is an ARP Response (used in spoofing)
        if packet[scapy.ARP].op == 2:
            ip_address = packet[scapy.ARP].psrc
            mac_address = packet[scapy.ARP].hwsrc
            print(f"[+] ARP Response: {ip_address} is at {mac_address}")
            print("[INFO] Monitoring for potential ARP spoofing/MITM activity...")

# Start the sniffer on the default Ethernet interface
sniff("eth0")