import sys
import time
import random
from scapy.all import *
import socket

packetCount = 0
def checkPackets(packet):

    IP = packet[1];
    TCP = packet[2]


    if IP.src =="192.168.0.18":
        print "PACKET!"



#Main
#Usage: SourceIP,TTL
print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

global TTLkey
TTLkey = sys.argv[1]

#1. Always be listening for that control packet
sniff(filter="ip",prn=checkPackets)
