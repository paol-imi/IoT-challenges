from scapy.contrib.mqtt import MQTT
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

count = 0
willMessagesSent = 0
ips = set([])
packets = rdpcap('./file.pcapng')


# Check if the topic starts with "university"
def starts_with_university(topic):
    return topic == b"university" or (topic is not None and (topic.decode("utf-8").startswith("university/")))


# Check if two topics match
def topics_match(sub_topic, pub_topic):
    # TODO: We don't handle the case where we have wildcard, we trow an exception in case so we know if they are present
    #  in the pcap file
    assert ("+" not in sub_topic.decode("utf-8") and "#" not in sub_topic.decode("utf-8"))
    return sub_topic == pub_topic


# Get the topics from a MQTT PUBLISH packet
def get_topics_from_publish_msg(packet):
    topics = []
    k = 0
    # TODO: Find a better way. I didn't find any API to loop trough the topics in a reasonable amount of time.
    #   With some trial and error, I found out that I can access the packets using numerical indexes so I'll do that.
    while True:
        try:
            # We just access the message with [k], if it is not present it will just trow and end the loop
            topics.append((packet[MQTT][k].topic, packet[MQTT][k].value))
            # We increment by 2 because the topics are repeated each time
            k += 2
        except:
            break
    return topics


# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    conn = packets[i]
    # If the packet has MQTT and the type is 1 (CONNECT)
    if MQTT in conn and conn[MQTT].type == 1 and starts_with_university(conn[MQTT].willtopic):
        # For each packet after the current packet
        count += 1
        for j in range(i + 1, len(packets)):
            # Get the packet
            pub = packets[j]
            # If the packet has MQTT and the type is 3 (PUBLISH)
            if (MQTT in pub and pub[MQTT].type == 3 and
                    # If the source and destination IP addresses are the same
                    pub[IP].src == conn[IP].dst and
                    # If the source and destination ports are the same
                    conn[TCP].dport == pub[TCP].sport):
                # For each topic in the SUBSCRIBE packet
                for (topic, value) in get_topics_from_publish_msg(pub):
                    # If the topic matches the topic of the PUBLISH packet
                    if topics_match(topic, pub[MQTT].topic) and value == conn[MQTT].willmsg:
                        # Increment the counter
                        willMessagesSent += 1
                        break

# Print the results
print("count: ", count)
print("willMessagesSent: ", willMessagesSent)
