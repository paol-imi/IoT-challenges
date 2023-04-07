from scapy.contrib.coap import CoAP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap

count = 0
helloCount = 0
ips = set([])
usedIds = set([])
packets = rdpcap('./file.pcapng')

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    packet = packets[i]
    # If the packet has DNS and is a response (QR flag is set to 1)
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
        for j in range(packet[DNS].ancount):
            # If the answer is an IP record for the coap.me server and the type is A or AAAA
            if packet[DNS].an[j].rrname == b'coap.me.' and packet[DNS].an[j].type in [1, 28]:
                # Add the IP address of the HiveMQ broker to the set
                ips.add(packet[DNS].an[j].rdata)

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    delete = packets[i]
    # If the packet has CoAP, it is a delete request (code 4) and the destination IP is the coap.me server
    if CoAP in delete and delete[CoAP].code == 4 and delete[IP].dst in ips:
        isHelloPath = False
        # Loop through the options of the CoAP packet
        for option in delete[CoAP].options:
            # If the option is a Uri-Path and the value is 'hello'
            if option[0] == 'Uri-Path' and option[1] == b'hello':
                # Set the hello flag to true
                isHelloPath = True
                break

        didFound = False
        # For each packet in the pcap file
        for j in range(i + 1, len(packets)):
            # Get the packet
            response = packets[j]

            # If the packet has CoAP and the code is 2.XX Content (65-95)
            if (j not in usedIds and CoAP in response and 66 <= response[
                CoAP].code <= 66 and
                    # The packet is a response to the delete request
                    ((response[CoAP].token != b'' and response[CoAP].token == delete[CoAP].token) or response[
                        CoAP].msg_id == delete[CoAP].msg_id) and
                    # The destination IP of the response is the source IP of the delete request and the source IP of the
                    # response is the destination IP of the delete request
                    IP in response and response[IP].dst == delete[IP].src and response[IP].src == delete[IP].dst and
                    response[UDP].dport == delete[UDP].sport and response[UDP].sport == delete[UDP].dport):
                # Set the found flag to true
                usedIds.add(j)
                response[CoAP].show()
                didFound = True
                break

        # If no 2.XX response was found
        if not didFound:
            count += 1
            # If the path is 'hello'
            if isHelloPath:
                # Increment the hello count
                helloCount += 1

# Print the results
print("count: ", count)
print("hello count: ", helloCount)
