import sys
import time
import random
from scapy.all import *
import socket

packetCount = 0
def checkPackets(packet):

    IP = packet[1];
    TCP = packet[2]

    if IP.ttl == TTLkey:
        print "PACKET!"
        print IP.show()
        print "IP identification is " + str(IP.id)
        print "S Port is " + str(TCP.sport)

        #Convert to binary
        print IP.id
        IPbin = bin(IP.id)
        print IPbin
        seg1 = IPbin[2:10]
        seg2 = IPbin[10:21]
        print seg1
        print seg2

        print TCP.sport
        SPbin = bin(TCP.sport)
        print SPbin
        # seg3 = SPbin[2:10]
        # seg4 = SPbin[10:21]
        # print seg3
        # print seg4









#Main
#Usage: SourceIP,TTL
print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)


global TTLkey
TTLkey = int(sys.argv[1])

#1. Always be listening for that control packet
sniff(filter="ip",prn=checkPackets)
