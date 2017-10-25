#/bin/sh

iptables -I INPUT -s 0.0.0.0 -p udp -m statistic --mode random --probability 0.5 -j DROP
