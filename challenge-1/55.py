from datetime import datetime, time

import pytz
from scapy.contrib.mqttsn import MQTTSN, PUBLISH
from scapy.layers.inet import UDP
from scapy.packet import bind_bottom_up, bind_layers
from scapy.utils import rdpcap

# Set the MQTT-SN port
bind_bottom_up(UDP, MQTTSN, sport=1885)
bind_bottom_up(UDP, MQTTSN, dport=1885)
bind_layers(UDP, MQTTSN, dport=1885, sport=1885)

count = 0
ips = set([])
packets = rdpcap('./file.pcapng')
tz = pytz.timezone('Europe/Rome')


# Get the topics from a MQTT PUBLISH packet
def get_topics_ids_from_publish_msg(packet):
    topics = []
    k = 0
    # TODO: Find a better way. I didn't find any API to loop trough the topics in a reasonable amount of time.
    #   With some trial and error, I found out that I can access the packets using numerical indexes so I'll do that.
    while True:
        try:
            # We just access the message with [k], if it is not present it will just trow and end the loop
            topics.append(packet[MQTTSN][k])
            # We increment by 2 because the topics are repeated each time
            k += 2
        except:
            break
    return topics


# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    pub = packets[i]
    # The packet has MQTT-SN and the type is PUBLISH and the topic id is 9
    if (MQTTSN in pub and pub[MQTTSN].type == PUBLISH and
            # We also check for UDP to be present in the packet, because there are also ICMP responses that we need
            # to discard:
            UDP in pub):

        dt = datetime.fromtimestamp(float(pub.time), pytz.utc)
        # Convert the datetime to Milan timezone
        dt_milan = dt.astimezone(tz)
        # The packet is sent after 15:16
        if dt_milan.time() >= time(15, 16):
            # Increment the counter
            count += 1

        # For each topic in the PUBLISH packet
        for tid in get_topics_ids_from_publish_msg(pub):
            # If the topic matches the topic of the PUBLISH packet
            if tid == 9:
                # Get the packet
                packet = packets[i]
                # Get the datetime of the packet
                dt = datetime.fromtimestamp(float(packet.time), pytz.utc)
                # Convert the datetime to Milan timezone
                dt_milan = dt.astimezone(tz)

                # The packet is sent after 15:16
                if dt_milan.time() >= time(15, 16):
                    # Increment the counter
                    count += 1
                break

print("count: ", count)
