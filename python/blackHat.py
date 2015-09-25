import sys
import time
import random
from scapy.all import *
import socket



## Helper Functions
def craftControlPacket(option,targetIP,listeningIP):



    #If it's time to send a control packet

    #1.A Split first 8 bits of IP address into the IP identification field
    print(listeningIP)

    if option == "1":
        #1.a Grab the current IP address in bits.
        bits_listIP = socket.inet_aton(listeningIP)
        address  = ([ord(i) for i in bits_listIP])
        #print(address)
        hexAddress =([hex(i) for i in address])
        #print(hexAddress)
        binAddress = ([bin(int(i, 16))[2:].zfill(8) for i in hexAddress])
        print binAddress[0]
        print binAddress[1]
        IP_ident_bin = binAddress[0]+binAddress[1]
        print IP_ident_bin
        IP_ident = int(IP_ident_bin,2)

        #1.B split the last 8 bits of the IP address into the TCP source port
        print binAddress[2]
        print binAddress[3]
        TCP_srcPort_bin = binAddress[2]+binAddress[3]
        print TCP_srcPort_bin
        TCP_srcPort = int(htons(TCP_srcPort_bin,2))
        print TCP_srcPort
        pkt = IP(src=listeningIP,dst=targetIP, id=IP_ident, ttl=71)/TCP(sport=TCP_srcPort, dport=80, flags="C")

        return pkt

    #Just sending a heartbeat
    else:
        print "heartbeat!"





# Main

print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

send(craftControlPacket(sys.argv[1],sys.argv[2],sys.argv[3]));
