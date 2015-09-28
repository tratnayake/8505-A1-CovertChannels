blackHat must stop ping replies
# echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all

to re-enable
# echo "0" >  /proc/sys/net/ipv4/icmp_echo_ignore_all