import sys
import time
import random
from scapy.all import *
import socket


def checkPackets()

#1. Always be listening for that control packet
sniff(filter="ip",prn=checkPackets)
