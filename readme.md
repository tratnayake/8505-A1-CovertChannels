## INITIAL SETTINGS

1. blackHat must stop ping replies
# echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all

2. Install Python on Linux
https://www.python.org/

3. Install SCAPY on Linux
pip install scapy

****to re-enable  pings after testingafter testing****
# echo "0" >  /proc/sys/net/ipv4/icmp_echo_ignore_all

##Running COMPROMISEDHOST.py
1. sudo python compromisedHost.py <ttlKey>
e.g. sudo python compromisedHost.py 71

2. Follow prompts on screen to send and receive

## RUNNING BLACKHAT.PY (Note: Compromised Host must be running first)
1. sudo python blackhat.py <targetIP><listeningIP><spoofedIP><TTLkey>

e.g. sudo python blackhat.py 192.168.1.103 192.168.1.102 8.8.8.8 71

2. Follow prompts on screen to send and receive
