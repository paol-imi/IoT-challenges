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

        # For each packet after the current packet
        for j in range(0, len(packets)):
            # Get the packet
            pubOrConn = packets[j]
            # If the packet has MQTT and the type is 3 (PUBLISH)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 3 and pubOrConn[MQTT].QOS == 1 and
                    # If the packet arrive from the HiveMQ broker
                    IP in pubOrConn and pubOrConn[IP].dst == conn[IP].src and
                    conn[TCP].sport == pubOrConn[TCP].dport):
                # Increment the counter

                k = 0
                # pubOrConn[MQTT].show()
                while True:
                    try:
                        print(pubOrConn[MQTT][k].topic)
                        pubOrConn[MQTT][k]
                        k += 1
                    except:
                        break

                count += k / 2
                print(i)

            # If the packet has MQTT and the type is 1 (CONNECT)
            if (False and MQTT in pubOrConn and pubOrConn[MQTT].type == 1 and
                    # If the packet arrive from the HiveMQ broker
                    conn[IP].src == pubOrConn[IP].src and pubOrConn[IP].dst == conn[IP].dst and conn[TCP].sport ==
                    pubOrConn[TCP].dport):
                # break the loop
                break

# Print the results
print("count: ", count)
