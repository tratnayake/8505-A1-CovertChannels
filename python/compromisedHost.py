import sys
import time
import random
from scapy.all import *
import socket


#Function takes in IP identification field & TCP source port data as ints, and then deconstructs them
# to construct the IP address
def deconstructIP(IP_id,TCP_sport):

    print "===DECONSTRUCTING IP ADDRESS==="
    print "IP id is " + str(IP_id)
    print "TCP Sport is" + str(TCP_sport)
    #convert to bits
    partition1 = bin(IP_id)[2:].zfill(8)
    partition2 = bin(TCP_sport)[2:].zfill(8)

    if len(partition1) < 16:
        partition1 = padPartition(partition1)
    if len(partition2) < 16:
        partition2 = padPartition(partition2) 
        
    seg1 = partition1[0:8]
    seg2 = partition1[8:16]
        #print "seg1 = " + seg1
        #print "seg2 = " + seg2

    seg3 = partition2[0:8]
    seg4 = partition2[8:16]
        #print "seg3 = " + seg3
        #print "seg4 = " + seg4
    
    print "IP Address " + str(int(seg1,2))+"."+str(int(seg2,2))+"."+str(int(seg3,2))+"."+str(int(seg4,2))
    

#If a partition is less than 16 bits (e.g. x.x.0.11 would only show up at as 101100001011), pad with necessary 0s
def padPartition(partition):
    partition = int(partition,2)
    partition = format(partition,'016b')
    return partition
    

packetCount = 0
def checkPackets(packet):

    IP = packet[1];
    TCP = packet[2]

    if IP.ttl == TTLkey:
        print "PACKET!"
        print IP.show()

        IP_id = IP.id
        TCP_sport = TCP.sport

        print "IP identification is " + str(IP_id)
        print "S Port is " + str(TCP_sport)

        deconstructIP(IP_id, TCP_sport)



        
#Main
#Usage: SourceIP,TTL
print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)


global TTLkey
TTLkey = int(sys.argv[1])

#1. Always be listening for that control packet
sniff(filter="ip",prn=checkPackets)
