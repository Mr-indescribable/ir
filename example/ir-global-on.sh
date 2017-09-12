#!/bin/sh

if [ $UID != 0 ]
then
	echo 'Permission denied'
	exit
fi


# your server's IP address
REMOTE_ADDR=

################################# TCP
iptables -t nat -N IR_TCP

iptables -t nat -A IR_TCP -d 0.0.0.0/8 -j RETURN
iptables -t nat -A IR_TCP -d 10.0.0.0/8 -j RETURN
iptables -t nat -A IR_TCP -d 127.0.0.0/8 -j RETURN
iptables -t nat -A IR_TCP -d 169.254.0.0/16 -j RETURN
iptables -t nat -A IR_TCP -d 172.16.0.0/12 -j RETURN
iptables -t nat -A IR_TCP -d 192.168.0.0/16 -j RETURN
iptables -t nat -A IR_TCP -d 224.0.0.0/4 -j RETURN
iptables -t nat -A IR_TCP -d 240.0.0.0/4 -j RETURN
iptables -t nat -A IR_TCP -d ${REMOTE_ADDR}/32 -j RETURN
iptables -t nat -A IR_TCP -p tcp -j REDIRECT --to-ports 60040
iptables -t nat -A OUTPUT -p tcp -j IR_TCP


################################# UDP
ip rule add fwmark 1 table 100
ip route add local default dev lo table 100

iptables -t mangle -N IR_UDP
iptables -t mangle -N IR_UDP_MARK

iptables -t mangle -A IR_UDP_MARK -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A IR_UDP_MARK -d ${REMOTE_ADDR}/32 -j RETURN

iptables -t mangle -A IR_UDP -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A IR_UDP -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A IR_UDP -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A IR_UDP -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A IR_UDP -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A IR_UDP -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A IR_UDP -d ${REMOTE_ADDR}/32 -j RETURN
iptables -t mangle -A IR_UDP -s ${REMOTE_ADDR}/32 -j RETURN

iptables -t mangle -A IR_UDP_MARK -p udp -j MARK --set-mark 1
iptables -t mangle -A IR_UDP -p udp -j TPROXY --on-port 60050 --tproxy-mark 0x01/0x01

iptables -t mangle -A OUTPUT -j IR_UDP_MARK
iptables -t mangle -A PREROUTING -j IR_UDP

sh -c 'echo nameserver 8.8.4.4 > /etc/resolv.conf'
sh -c 'echo nameserver 8.8.8.8 >> /etc/resolv.conf'
