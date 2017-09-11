#!/bin/sh

sudo ip rule add fwmark 1 table 100
sudo ip route add local default dev lo table 100

sudo iptables -t mangle -N UDP_REDIR_TEST
sudo iptables -t mangle -N TP_MARK

# my remote server address is 192.168.122.164
# my localhost address is 192.168.122.171
sudo iptables -t mangle -A TP_MARK -d 0.0.0.0/8 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 10.0.0.0/8 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 127.0.0.0/8 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 169.254.0.0/16 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 172.16.0.0/12 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 224.0.0.0/4 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 240.0.0.0/4 -j RETURN
# ignore all packet to remote server
sudo iptables -t mangle -A TP_MARK -d 192.168.122.164/32 -j RETURN
sudo iptables -t mangle -A TP_MARK -d 192.168.122.23/32 -j RETURN

sudo iptables -t mangle -A UDP_REDIR_TEST -d 0.0.0.0/8 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 10.0.0.0/8 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 127.0.0.0/8 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 169.254.0.0/16 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 172.16.0.0/12 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 224.0.0.0/4 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 240.0.0.0/4 -j RETURN
# need to ignore all packet to/from remote server
# and also need to ignore all packet to localhost
sudo iptables -t mangle -A UDP_REDIR_TEST -d 192.168.122.164/32 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -s 192.168.122.164/32 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 192.168.122.23/32 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -s 192.168.122.23/32 -j RETURN
sudo iptables -t mangle -A UDP_REDIR_TEST -d 192.168.122.171/32 -j RETURN

sudo iptables -t mangle -A TP_MARK -p udp -j MARK --set-mark 1

# my local server's "listen_udp_port" is 60050
sudo iptables -t mangle -A UDP_REDIR_TEST -p udp -j TPROXY --on-port 60050 --tproxy-mark 0x01/0x01

sudo iptables -t mangle -A OUTPUT -j TP_MARK
sudo iptables -t mangle -A PREROUTING -j UDP_REDIR_TEST
