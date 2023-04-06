from scapy.contrib.mqtt import MQTT
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

count = 0
topicCount = 0
ips = set([])
packets = rdpcap('./file.pcapng')
withSLWildcards = set([])
withRoom0Topic = set([])

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    packet = packets[i]
    # If the packet has DNS and is a response (QR flag is set to 1)
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
        for i in range(packet[DNS].ancount):
            # If the answer is an IP record for the Mosquitto broker and the type is 1 (A) or 28 (AAAA)
            if packet[DNS].an[i].rrname == b'test.mosquitto.org.' and packet[DNS].an[i].type in [1, 28]:
                # Add the IP address of the mosquitto broker to the set
                ips.add(packet[DNS].an[i].rdata)

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    sub = packets[i]
    # If the packet has MQTT and the type is 8 (SUBSCRIBE) and the destination is the mosquitto broker
    if MQTT in sub and sub[MQTT].type == 8 and sub[IP].dst in ips:
        hasSLWildcard = False
        hasRoom0Topic = False
        for topic in sub[MQTT].topics:
            if b'+' in topic.topic:
                hasSLWildcard = True
            if topic.topic in [b"hospital/room2/area0", b"+/room2/area0", b"hospital/+/area0", b"hospital/room2/+",
                               b"+/+/area0", b"+/room2/+", b"hospital/+/+", b"+/+/+", b"hospital/room2/#",
                               b"hospital/#", b"#", ]:
                hasRoom0Topic = True

        for j in range(i, len(packets)):
            suback = packets[j]
            if (MQTT in suback and suback[MQTT].type == 9 and sub[MQTT].msgid == suback[MQTT].msgid and
                    IP in sub and IP in suback and sub[IP].src == suback[IP].dst and sub[IP].dst == suback[IP].src and
                    sub[TCP].ack == suback[TCP].seq and sub[TCP].sport == suback[TCP].dport and sub[TCP].dport ==
                    suback[TCP].sport):
                if hasSLWildcard:
                    withSLWildcards.add((sub[IP].src, sub[TCP].sport))
                if hasRoom0Topic:
                    withRoom0Topic.add((sub[IP].src, sub[TCP].sport))
                break

print("count: ", len(withSLWildcards))
print("topic count: ", len(withRoom0Topic.intersection(withSLWildcards)))
