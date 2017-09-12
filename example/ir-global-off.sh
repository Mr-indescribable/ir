#!/bin/sh

if [ $UID != 0 ]
then
	echo 'Permission denied'
	exit
fi


/usr/lib/systemd/scripts/iptables-flush

ip rule delete fwmark 1 table 100
ip route delete local default dev lo table 100

sh -c 'echo nameserver 192.168.1.1 > /etc/resolv.conf'
