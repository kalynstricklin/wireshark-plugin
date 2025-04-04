from scapy.all import rdpcap
import pandas as pd

from model.models import random_forest_predict, db_scan_cluster


def inspect_packets(pcap_path):
    # "../data/raw/dns-remoteshell.pcap"
    packets = rdpcap(pcap_path)  # reads in the .pcap file and returns the list of packets

    # iterate through each packet in the list
    for packet in packets:
        print(packet.summary())

        if (packet.haslayer("IP")):
            print("Source IP: ", packet["IP"].src)


# function to tag sus behavior
def is_suspicious(row):
    info = str(row["Info"]).lower()
    protocol = str(row['Protocol']).lower()
    length = str(row['Length']).lower()

    if protocol == "dns":
        if len(info.split()) > 20:
            return 1
        # malformed domains == sus
        if "www.www.com.lan" in info:
            return 1
        if any(domain in info for domain in ["uthscsa.edu", "njit.edu"]):
            return 1

    # telnet == sus
    if "telnet" in str(protocol).lower():
        return 1

    # repeated SYNs to ports like 21 (FTP) or 23 (Telnet) == sus
    if "[syn]" in info and (">  21" in info or ">  23" in info):
        return 1

    if "[rst, ack]" in info and float(length) < 100:
        return 1

    if "bad udp length" in info:
        return 1

    if "fragmented" in info or "reassembled" in info:
        return 1

    if protocol == "loop":
        return 1

    if protocol == "arp" and "who has" in info:
        return 1

    if 'NTLMSSP_AUTH' in info or 'STATUS_ACCESS_DENIED' in info:
        return 1

    if protocol == 'smb2' and 'encrypted' in info and int(length) > 500:
        return 1

    # not suspicious
    return 0


def label_files(csv_in, csv_out):
    df = pd.read_csv(csv_in)
    # apply sus function and export labeled data to csv
    df['Suspicious'] = df.apply(is_suspicious, axis=1)
    df.to_csv(csv_out, index=False)
    print(f"Saved labeled data to {csv_out}")


def run_models_clustering(csv_path, model_path):
    random_forest_predict(csv_path, model_path)
    labels, clusters, noise = db_scan_cluster(csv_path)
    print(f"Labels {labels}, Clusters: {clusters}, Noise: {noise}")


if __name__ == "__main__":
    def main():
        # PACKETS
        # inspect_packets("../data/raw/dns-remoteshell.pcap")

        # LABELS
        label_files("../data/dns-remoteshell.csv", "../data/labeled/labeled_dns.csv")
        label_files("../data/teardrop.csv", "../data/labeled/label_teardrop.csv")
        label_files("../data/smb-on-windows-10.csv", "../data/labeled/label_smb-on-windows-10.csv")

        # MODELS
        run_models_clustering("../data/labeled/labeled_dns.csv", 'rf_suspicion_model_dns.pkl')
        # run_models_and_clustering("../data/labeled/label_teardrop.csv", 'rf_suspicion_model_teardrop.pkl')
        run_models_clustering("../data/labeled/label_smb-on-windows-10.csv", 'rf_suspicion_model_smb.pkl')

main()
