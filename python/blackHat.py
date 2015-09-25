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
        #print binAddress
        IP_ident_bin = binAddress[0]+binAddress[1]
        #print IP_ident_bin
        IP_ident = int(IP_ident_bin,2)

        #1.B split the last 8 bits of the IP address into the TCP source port
        TCP_srcPort_bin = binAddress[2]+binAddress[3]
        TCP_srcPort = int(TCP_srcPort_bin,2)
        pkt = IP(src="192.168.1.108",dst="192.168.1.102", id=IP_ident, ttl=71)/TCP(sport=TCP_srcPort, dport=80, flags="C")

        return pkt

    #Just sending a heartbeat
    else:
        print "heartbeat!"





# Main

print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

send(craftControlPacket(sys.argv[1],sys.argv[2],sys.argv[3]));
