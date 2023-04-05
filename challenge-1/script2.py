from scapy.contrib.coap import CoAP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.utils import rdpcap

count = 0
helloCount = 0
ips = set([])
packets = rdpcap('./file.pcapng')

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    packet = packets[i]
    # If the packet has DNS and the QR flag is set to 1, meaning it is a response
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
        for i in range(packet[DNS].ancount):
            # If the answer is an IP record for the HiveMQ broker
            if packet[DNS].an[i].rrname == b'coap.me.' and packet[DNS].an[i].type in [1, 28]:
                # Add the IP address of the HiveMQ broker to the set
                ips.add(packet[DNS].an[i].rdata)

for i in range(0, len(packets)):
    # Get the packet
    delete = packets[i]
    # and CoAP in pkt and pkt[CoAP].code == "4.04":
    if CoAP in delete and delete[CoAP].code == 4 and delete[IP].dst == '134.102.218.18':
        isHelloPath = False
        for option in delete[CoAP].options:
            if option[0] == 'Uri-Path' and option[1] == b'hello':
                isHelloPath = True
                break

        didFound = False
        for response in packets:
            if (IP in response and CoAP in response and
                    (response[CoAP].code >= 65 or response[CoAP].code <= 95) and
                    ((response[CoAP].token != b'' and response[CoAP].token == delete[CoAP].token) or response[
                        CoAP].msg_id == delete[CoAP].msg_id) and
                    response[IP].dst == delete[IP].src and response[IP].src == delete[IP].dst):
                didFound = True
                break

        if not didFound:
            if isHelloPath:
                helloCount += 1
            else:
                count += 1

print("count: ", count)
print("tot count: ", helloCount)
