from datetime import datetime, time

import pytz
from scapy.contrib.mqttsn import MQTTSN, PUBLISH
from scapy.layers.inet import UDP
from scapy.packet import bind_bottom_up, bind_layers
from scapy.utils import rdpcap

bind_bottom_up(UDP, MQTTSN, sport=1885)
bind_bottom_up(UDP, MQTTSN, dport=1885)
bind_layers(UDP, MQTTSN, dport=1885, sport=1885)

# AAAAAA
# TODO: CHECK FOR NOT ICMP

count = 0
ips = set([])
packets = rdpcap('./file.pcapng')
tz = pytz.timezone('Europe/Rome')

for i in range(0, len(packets)):
    if MQTTSN in packets[i]:
        packet = packets[i]
        dt = datetime.fromtimestamp(float(packet.time), pytz.utc)
        dt_milan = dt.astimezone(tz)

        print(packet[MQTTSN].tid)
        if dt_milan.time() >= time(15, 16) and packet[MQTTSN].type == PUBLISH and packet[MQTTSN].tid == 9:
            print(dt_milan)
            count += 1

print("count: ", count)
