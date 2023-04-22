from scapy.contrib.mqtt import MQTT
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

count = 0
ips = set([])
packets = rdpcap('./file.pcapng')

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    packet = packets[i]
    # If the packet has DNS and is a response (QR flag is set to 1)
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
        for i in range(packet[DNS].ancount):
            # If the answer is an IP record for the HiveMQ broker (broker.hivemq.com) and the type is 1 (A) or 28 (AAAA)
            if packet[DNS].an[i].rrname == b'broker.hivemq.com.' and packet[DNS].an[i].type in [1, 28]:
                # Add the IP address of the HiveMQ broker to the set
                ips.add(packet[DNS].an[i].rdata)

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    conn = packets[i]
    # If the packet has MQTT and the type is 1 (CONNECT) and the protocol level is 5
    if (MQTT in conn and conn[MQTT].type == 1 and conn[MQTT].protolevel == 5 and
            # If the packet is directed to the HiveMQ broker
            IP in conn and conn[IP].dst in ips):

        isConnected = False
        # For each packet after the current packet
        for j in range(i + 1, len(packets)):
            connack = packets[j]
            # If the packet has MQTT and the type is 1 (CONNECT) and the protocol level is 5
            if (MQTT in connack and connack[MQTT].type == 2 and
                    # If the packet is directed to the HiveMQ broker
                    IP in connack and connack[IP].dst == conn[IP].src and connack[IP].src == conn[IP].dst and
                    # If the ports are the same
                    conn[TCP].sport == connack[TCP].dport and conn[TCP].dport == connack[TCP].sport):
                # Increment the count
                isConnected = True
                break

        if not isConnected:
            continue

        # For each packet after the current packet
        for j in range(i + 1, len(packets)):
            # Get the packet
            pubOrConn = packets[j]
            # If the packet has MQTT and the type is 4 (PUBACK)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 4 and
                    # If the packet arrive from the HiveMQ broker
                    IP in pubOrConn and pubOrConn[IP].dst == conn[IP].src and pubOrConn[IP].src == conn[IP].dst and
                    # If the ports are the same
                    conn[TCP].sport == pubOrConn[TCP].dport):
                count += 1

            # If the packet has MQTT and the type is 1 (CONNECT)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 1 and
                    # If the packet arrive from the HiveMQ broker
                    IP in pubOrConn and pubOrConn[IP].dst == conn[IP].src and pubOrConn[IP].src == conn[IP].dst and
                    # If the ports are the same
                    conn[TCP].sport == pubOrConn[TCP].dport and conn[TCP].dport == pubOrConn[TCP].sport):
                # break the loop
                break

# Print the results
print("count: ", count)
