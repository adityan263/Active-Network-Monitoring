from scapy.all import *

def ICMPpacket(source, destination, time, t, raw_load):
	packet = IP(src=source, dst=destination, ttl = time)/ICMP(type=t)/raw_load
	send(packet)
	packet.show()
	return packet

def TCPpacket(destination, sp, dp) :
	packet = IP(dst=destination)/TCP(sport=sp, dport=dp)
	send(packet)
	packet.show()
	return packet

def UDPpacket(destination, sp, dp):
	packet = IP(dst=destination)/UDP(sport=sp, dport=dp)
	send(packet)
	packet.show()
	return packet

def TraceRoute(destination, m):
	traceroute([destination], maxttl = m)

#sr1(IP(dst="10.1.99.2")/UDP()/DNS(rd=1,qd=DNSQR(qname="citrix.com",qtype= "NS")))
#output=sr(IP(dst='google.com')/ICMP())
#result, unanswered=output
#print result
