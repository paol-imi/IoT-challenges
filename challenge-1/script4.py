from scapy.contrib.mqtt import MQTT
from scapy.layers.inet import IP
from scapy.utils import rdpcap

count = 0
ips = set([])
packets = rdpcap('./file.pcapng')


def startsWithUniversity(topic):
    print(topic)
    return topic == b"university" or (topic is not None and "university/" in topic.decode("utf-8"))


# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    conn = packets[i]
    # If the packet has MQTT and the type is 1 (CONNECT)
    if MQTT in conn and conn[MQTT].type == 1 and startsWithUniversity(conn[MQTT].willtopic):
        # For each packet after the current packet
        for j in range(i + 1, len(packets)):
            # Get the packet
            pub = packets[j]
            # If the packet has MQTT and the type is 3 (PUBLISH)
            if (MQTT in pub and pub[MQTT].type == 3 and pub[MQTT].topic == conn[MQTT].willtopic and
                    pub[MQTT].value == conn[MQTT].willmsg and
                    # If the packet arrive from the HiveMQ broker
                    IP in pub and IP in conn and pub[IP].src == conn[IP].dst):
                # Increment the counter
                count += 1

# Print the results
print("count: ", count)
