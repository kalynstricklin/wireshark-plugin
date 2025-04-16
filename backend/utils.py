import matplotlib

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import numpy as np
# from scapy.all import rdpcap
# import pandas as pd
#
# def inspect_packets(pcap_path):
#     # "../data/raw/dns-remoteshell.pcap"
#     packets = rdpcap(pcap_path)  # reads in the .pcap file and returns the list of packets
#
#     # iterate through each packet in the list
#     for packet in packets:
#         print(packet.summary())
#
#         if (packet.haslayer("IP")):
#             print("Source IP: ", packet["IP"].src)


# function to tag sus packets
def is_suspicious(row):
    info = str(row.get("Info", "")).lower()
    protocol = str(row.get('Protocol', '')).lower()
    length = str(row.get('Length', '0')).lower()

    if protocol == "dns":
        if len(info.split()) > 20 or "www.www.com.lan" in info:
            return 1
        if any(domain in info for domain in ["uthscsa.edu", "njit.edu"]):
            return 1
    if "telnet" in protocol:
        return 1
    if "[syn]" in info and any(p in info for p in [">  21", ">  23"]):
        return 1
    if "[rst, ack]" in info and float(length) < 100:
        return 1
    if "bad udp length" in info or "fragmented" in info or "reassembled" in info:
        return 1
    if protocol == "loop":
        return 1
    if protocol == "arp" and "who has" in info:
        return 1
    if 'ntlmssp_auth' in info or 'status_access_denied' in info:
        return 1
    if protocol == 'smb2' and 'encrypted' in info and int(length) > 500:
        return 1
    return 0

