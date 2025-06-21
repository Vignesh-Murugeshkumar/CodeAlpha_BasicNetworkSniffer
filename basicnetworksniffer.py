from scapy.all import sniff, wrpcap, IP, Raw
from scapy.layers.inet import TCP, UDP, ICMP
captured_packets = []
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        source = ip_layer.src
        destination = ip_layer.dst
        protocol = ip_layer.proto
        # Corrected protocol dictionary lookup
        protocol_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, "Unknown Protocol")
        print(f"Protocol Name: {protocol_name}")
        print(f"Source = {source}")
        print(f"Destination = {destination}")
        print(f"Protocol Number = {protocol}")
        # TCP/UDP port handling
        if protocol == 6 and TCP in packet:
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif protocol == 17 and UDP in packet:
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        else:
            print("Ports: None")
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload =", payload)
        else:
            print("Payload = None")

        print("*" * 100)
        captured_packets.append(packet)

def main():
    print("[*] Starting packet capture (limit 10 packets)...")
    sniff(prn=packet_callback, filter="ip", store=0, count=10)
    wrpcap("captured_packets1.pcap", captured_packets)
    print("[*] 10 packets captured and saved to 'captured_packets1.pcap'")
if __name__ == "__main__":
    main()
