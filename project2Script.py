#Python script to capture 15 Ethernet frames using the Scapy library

from scapy.all import *

print("Starting 15 frame packet capture...")
#defined my wireless interface name along with the count of packets to capture
packets = sniff(count=15, iface="Intel(R) Wi-Fi 6E AX211 160MHz")

#extract and print the source MAC address and the destination MAC address or each captured Ethernet fram
for packet in packets:
    print("-" * 50)
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")

    #check if the packet contains an IP layer, if yes, extract and print the IP version, source & destination IP addresses
    if packet.haslayer(IP):
        ip_version = packet[IP].version
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP Version: {ip_version}, Source IP: {src_ip}, Destination IP: {dst_ip}")
    
    #extract and print the first 42 bytes in hex format, and format the bytes for readability by printing 8 bytes per line, with a 
    #space between every 2 bytes
    raw_data = bytes(packet)[:42]
    hex_data = raw_data.hex()
    formated_hex = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]

    for i in range(0, len(formated_hex), 8):
        line = ' '.join(formated_hex[i:i+8])
        print(line)


print("-" * 50)
print("Packet capture complete.")