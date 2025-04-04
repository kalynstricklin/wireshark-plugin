from scapy.all import rdpcap
import pandas as pd

from model.backend import random_forest_predict, db_scan_cluster

if __name__ == "__main__":
    def main():

        # packets = rdpcap("../data/raw/dns-remoteshell.pcap") # reads in the .pcap file and returns the list of packets

        # iterate through each packet in the list
        # for packet in packets:
        #     print(packet.summary())

            # if(packet.haslayer("IP")):
            #     print("SOURCE IP: ", packet["IP"].src)


        # load in thr csv
        # df = pd.read_csv(".././data/dns-remoteshell.csv")
        #
        # # function to tag sus behavior
        # def is_suspicious(row):
        #     info = str(row["Info"]).lower()
        #     protocol = str(row['Protocol']).lower()
        #     length = str(row['Length']).lower()
        #
        #     if protocol == "dns":
        #         if len(info.split()) > 20:
        #             return 1
        #         # malformed domains == sus
        #         if "www.www.com.lan" in info:
        #             return 1
        #         if any(domain in info for domain in ["uthscsa.edu", "njit.edu"]):
        #             return 1
        #
        #     # telnet == sus
        #     if "telnet" in str(row['Protocol']).lower():
        #         return 1
        #
        #     # repeated SYNs to ports like 21 (FTP) or 23 (Telnet) == sus
        #     if "[syn]" in info and (">  21" in info or ">  23" in info):
        #         return 1
        #
        #     if "[rst, ack]" in info and float(length) < 100:
        #         return 1
        #
        #     if "bad udp length" in info:
        #         return 1
        #
        #     if "fragmented" in info or "reassembled" in info:
        #         return 1
        #
        #     if protocol == "loop":
        #         return 1
        #     if protocol == "arp" and "who has" in info:
        #         return 1
        #
        #     if 'NTLMSSP_AUTH' in info:
        #         return 1
        #
        #     if 'STATUS_ACCESS_DENIED' in info:
        #         return 1
        #
        #     if protocol == 'SMB2' and 'Encrypted' in info and int(length) > 500:
        #         return 1
        #
        #     # not suspicious
        #     return 0
        #
        # # apply sus function and export labeled data to csv
        # df['Suspicious'] = df.apply(is_suspicious, axis=1)
        # df.to_csv(".././data/labeled/labeled_dns.csv", index=False)
        # print("Suspicious data tagged and saved!")
        #
        #
        # df = pd.read_csv(".././data/teardrop.csv")
        #
        # df['Suspicious'] = df.apply(is_suspicious, axis=1)
        # df.to_csv(".././data/labeled/label_teardrop.csv", index=False)
        # print("Suspicious data tagged and saved!")
        #
        #
        # df = pd.read_csv(".././data/smb-on-windows-10.csv")
        #
        # df['Suspicious'] = df.apply(is_suspicious, axis=1)
        # df.to_csv(".././data/labeled/label_smb-on-windows-10.csv", index=False)
        # print("Suspicious data tagged and saved!")

        random_forest_predict(".././data/labeled/labeled_dns.csv", 'rf_suspicion_model_dns.pkl')
        # random_forest_predict(".././data/labeled/label_teardrop.csv") //might be bad
        random_forest_predict(".././data/labeled/label_smb-on-windows-10.csv", 'rf_suspicion_model_teardrop.pkl')

        labels, clusters, noise = db_scan_cluster(".././data/labeled/labeled_dns.csv")
        print(f"Labels {labels}, Clusters: {clusters}, Noise: {noise}")
        # db_scan_cluster(".././data/labeled/label_teardrop.csv") //might be bad
        labels, clusters, noise = db_scan_cluster(".././data/labeled/label_smb-on-windows-10.csv")
        print(f"Labels {labels}, Clusters: {clusters}, Noise: {noise}")
    main()
