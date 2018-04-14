import socket
import struct


class Ethernet:

    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac_addr = convert_mac_address(dest)
        self.src_mac_addr = convert_mac_address(src)
        #hex to decimal conversion
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]
        #print(self.src_mac_addr, self.dest_mac_addr)


def convert_mac_address(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src_ip_addr = convert_ip_address(src)
        self.target_ip_addr = convert_ip_address(target)
        self.data = raw_data[self.header_length:]

# Returns properly formatted IP address
def convert_ip_address(addr):
    return '.'.join(map(str, addr))


class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H H', raw_data[:6])
        self.data = raw_data[8:]

class IGMP:

    def __init__(self, raw_data):
        self.type, self.max_response_time, self.grp_addr = struct.unpack('! B B 2x 4s', raw_data[:8])
        self.data = raw_data[8:]

class ARP:

    def __init__(self, raw_data):
        self.operation, src_mac_addr, src_ip_addr, dest_mac_addr, dest_ip_addr = struct.unpack(
            '! 2s 6s 4s 6s 4s', raw_data[6:])
        #operation = 1 => request, operation = 2 =>response/reply
        #considering hardware type=1, hardware length=6
        self.src_mac_addr = convert_mac_address(src_mac_addr)
        self.dest_mac_addr = convert_mac_address(dest_mac_addr)
        #considering protocol type=0x0800, protocol length=4
        self.src_ip_addr = convert_ip_address(src_ip_addr)
        self.dest_ip_addr = convert_ip_address(dest_ip_addr)

class RARP:

    def __init__(self, raw_data):
        self.operation, src_mac_addr, src_ip_addr, dest_mac_addr, dest_ip_addr = struct.unpack(
            '! H 6s 4s 6s 4s', raw_data[6:])
        #operation = 3 => request, operation = 4 =>response/reply
        #considering hardware type=1, hardware length=6
        self.src_mac_addr = convert_mac_address(src_mac_addr)
        self.dest_mac_addr = convert_mac_address(dest_mac_addr)
        #considering protocol type=0x0800, protocol length=4
        self.src_ip_addr = convert_ip_address(src_ip_addr)
        self.dest_ip_addr = convert_ip_address(dest_ip_addr)

class IPv6:

    def __init__(self, raw_data):
        src_ip, dest_ip = struct.unpack('! 16s 16s', raw_data[8:])
        self.src_ip_addr = convert_ip_address(src_ip)
        self.dest_ip_addr = convert_ip_address(dest_ip)
        self.data = raw_data[40:]


class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data
