from scapy.all import *

load_contrib("coap")

pkts = rdpcap('./file.pcapng')

ips = ['134.102.218.18']

count = 0
helloCount = 0

for pkt1 in pkts:
    # and CoAP in pkt and pkt[CoAP].code == "4.04":
    if CoAP in pkt1 and pkt1[CoAP].code == 4 and pkt1[IP].dst == '134.102.218.18':
        for option in pkt[CoAP].options:
            print(option)
            if option[0] == 'Uri-Path' and option[1] == b'hello':
                helloCount += 1
        for pkt in pkts:
            if (IP in pkt and CoAP in pkt and (pkt[CoAP].code >= 65 or pkt[CoAP].code <= 95) and
                    ((pkt1[CoAP].token != b'' and pkt1[CoAP].token == pkt[CoAP].token) or pkt1[CoAP].msg_id == pkt[CoAP].msg_id) and
                    pkt1[IP].dst == pkt[IP].src and pkt1[IP].src == pkt[IP].dst):
                count += 1

                for option in pkt[CoAP].options:
                    print(option)
                    if option[0] == 'Uri-Path' and option[1] == b'hello':
                        helloCount += 1

                break

print("count: ", count)
print("tot count: ", helloCount)
