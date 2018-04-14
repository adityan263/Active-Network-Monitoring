from scapy.all import *

def ICMPpacket(source, destination, time, t, raw_load):
	packet = IP(src=source, dst=destination, ttl = time)/ICMP(type=t)/raw_load
	send(packet)
	packet.show()
	return packet

def TCPpacket(destination, sp, dp) :
	packet = IP(dst=destination)/TCP(sport=sp, dport=dp)
	send(packet)
#	packet.show()
	return packet

def UDPpacket(destination, sp, dp):
	packet = IP(dst=destination)/UDP(sport=sp, dport=dp)
	send(packet)
	packet.show()
	return packet

def TraceRoute(destination, m):
	traceroute([destination], maxttl = m)

def ARPpacket(hwsrcentry, pdstentry):
	packet = Ether(dst='ff:ff:ff:ff:ff:ff', src=hwsrcentry)/ARP(hwsrc=hwsrcentry, pdst=pdstentry)
	send(packet)
	packet.show()
	return packet


def valid_port(port):
	if port.isdigit() and (0 <= int(port) <= 65535):
		return True
	else:
		return False

def valid_ip(ip):
	a = ip.split('.')
	if not len(a) == 4:
		return False
	for item in a:
		if not 0 <= int(item) <= 255 :
			return False
	return True

def valid_hw(mac):
	a = mac.split(':')
	if not len(a) == 6:
		return False
	for items in a:
		if len(items) > 2:
			return False
		for i in items:
			if not (i.isdigit() or 'a' <= i <= 'f'):
				return False
	return True

