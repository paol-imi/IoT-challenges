from scapy.contrib.mqtt import MQTT
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

count = 0
ips = set([])
packets = rdpcap('./file.pcapng')


# Get the topics from a MQTT PUBLISH packet
def get_topics_qos_from_publish_msg(packet):
    topics = []
    k = 0
    # TODO: Find a better way. I didn't find any API to loop trough the topics in a reasonable amount of time.
    #   With some trial and error, I found out that I can access the packets using numerical indexes so I'll do that.
    while True:
        try:
            # We just access the message with [k], if it is not present it will just trow and end the loop
            topics.append(packet[MQTT][k].QOS)
            # We increment by 2 because the topics are repeated each time
            k += 2
        except:
            break
    return topics


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
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 3 and
                    # If the packet arrive from the HiveMQ broker
                    IP in pubOrConn and pubOrConn[IP].dst == conn[IP].src and
                    conn[TCP].sport == pubOrConn[TCP].dport):

                # Get the qoss of the topics
                qoss = get_topics_qos_from_publish_msg(pubOrConn)
                for qos in qoss:
                    # If the qos is 1
                    if qos == 1:
                        # Increment the counter
                        count += 1

            # If the packet has MQTT and the type is 1 (CONNECT)
            if (MQTT in pubOrConn and pubOrConn[MQTT].type == 1 and
                    # If the packet arrive from the HiveMQ broker
                    conn[IP].src == pubOrConn[IP].src and pubOrConn[IP].dst == conn[IP].dst and conn[TCP].sport ==
                    pubOrConn[TCP].dport):
                # break the loop
                break

# Print the results
print("count: ", count)
