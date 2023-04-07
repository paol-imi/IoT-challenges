from scapy.contrib.coap import CoAP
from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap

count = 0
countNON = 0
packets = rdpcap('./file.pcapng')

# For each packet in the pcap file
for i in range(0, len(packets)):
    # Get the packet
    notFound = packets[i]
    # Check if the packet is a CoAP packet and if it is a 404 response coming from the server
    if CoAP in notFound and notFound[CoAP].code == 132 and notFound[IP].src == '127.0.0.1':
        # For each packet before the current one
        for j in range(i - 1, 0, -1):
            # Get the packet
            get = packets[j]

            # Check if the packet is a CoAP packet and if it is a GET request coming from the client
            if (CoAP in get and get[CoAP].code == 1 and
                    # Check if the token or the message id of the GET request is the same as the one of the 404 response
                    ((get[CoAP].token != b'' and get[CoAP].token == notFound[CoAP].token)
                     or get[CoAP].msg_id == notFound[CoAP].msg_id) and
                    # Check if the source and destination IP addresses are the same
                    get[IP].dst == notFound[IP].src and get[IP].src == notFound[IP].dst and
                    # Check if the source and destination ports are the same
                    get[UDP].dport == notFound[UDP].sport and get[UDP].sport == notFound[UDP].dport):
                # If it is, increment the counter
                count += 1

                # Check if the GET request is non-confirmable
                if get[CoAP].type == 1:
                    # If it is, increment the counter
                    countNON += 1

                # Break the loop
                break

# Print the results
print("count: ", count)
print("count non-confirmable: ", countNON)
