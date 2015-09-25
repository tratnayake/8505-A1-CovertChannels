import sys
import time
import random
from scapy.all import *
import socket

packetCount = 0
def checkPackets(packet):
    if packet.[0][1].src =="192.168.0.18":
        global packetCount
        packetCount += 1
        return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)


#1. Always be listening for that control packet
sniff(filter="ip",prn=checkPackets)
