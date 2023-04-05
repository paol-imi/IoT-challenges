from scapy.utils import rdpcap
from scapy.layers.inet import IP
from scapy.contrib.mqtt import MQTT
from scapy.layers.dns import DNS, DNSRR

ips = []
count = 0
packets = rdpcap('./file.pcapng')
ips = ["52.29.173.150", "3.65.137.17"]

for i in range(0, len(packets)):
    packet = packets[i]
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
       print("---------")
       for i in range(packet[DNS].ancount):
           print(packet[DNSRR][i].rdata)

print(ips)

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    conn = packets[i]
    # If the packet has MQTT and the type is 1 (CONNECT) and the protocol level is 5
    if (MQTT in conn and conn[MQTT].type == 1 and conn[MQTT].protolevel == 5 and
            # If the packet is directed to the HiveMQ broker
            IP in conn and conn[IP].dst in ips):
        # For each packet after the current packet
        for j in range(i+1, len(packets)):
            # Get the packet
            pubOrConn = packets[j]
            # If the packet has MQTT and the type is 3 (PUBLISH)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 3 and pubOrConn[MQTT].QOS == 1 and
                    # If the packet arrive from the HiveMQ broker
                    IP in pubOrConn and pubOrConn[IP].src == conn[IP].dst and pubOrConn[IP].dst == conn[IP].src):
                # Increment the counter
                count += 1

            # If the packet has MQTT and the type is 1 (CONNECT)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 1 and
                    # If the packet arrive from the HiveMQ broker
                    conn[IP].src == pubOrConn[IP].src and pubOrConn[IP].dst == conn[IP].dst):
                # break the loop
                break

# Print the results
print("count: ", count)
