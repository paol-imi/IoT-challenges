from scapy.contrib.coap import CoAP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap

count = 0
helloCount = 0
ips = set([])
packets = rdpcap('./file.pcapng')

# We retrieve the IP addresses of the coap.me server
for i in range(0, len(packets)):
    # Get the packet
    packet = packets[i]
    # If the packet has DNS and is a response (QR flag is set to 1)
    if DNS in packet and packet[DNS].qr == 1:
        # Loop through the answer section of the DNS response
        for j in range(packet[DNS].ancount):
            # If the answer is an IP record for the coap.me server and the type is A or AAAA
            if packet[DNS].an[j].rrname == b'coap.me.' and packet[DNS].an[j].type in [1, 28]:
                # Add the IP address of the coap.me server to the set
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

            # If the packet has CoAP and the code is 2.02
            if (CoAP in response and response[CoAP].code == 66 and
                    # The packet is a response to the delete request
                    (response[CoAP].msg_id == delete[CoAP].msg_id or (
                            response[CoAP].token != b'' and response[CoAP].token == delete[CoAP].token)) and
                    # Check if the source and destination IP addresses are the same
                    response[IP].dst == delete[IP].src and response[IP].src == delete[IP].dst and
                    # Check if the source and destination ports are the same
                    response[UDP].dport == delete[UDP].sport and response[UDP].sport == delete[UDP].dport):
                # Set the found flag to true
                didFound = True
                break

        # If no 2.02 response was found
        if not didFound:
            # Increment the count
            count += 1
            # If the path is 'hello'
            if isHelloPath:
                # Increment the hello count
                helloCount += 1

# Print the results
print("count: ", count)
print("hello count: ", helloCount)
