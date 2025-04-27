import socket
import struct

class IPHeader:
    def __init__(self, source_ip, dest_ip, ttl=64):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.total_length = 0  # Length will be computed later
        self.id = 54321  # Identification field
        self.frag_offset = 0  # Fragmentation offset
        self.ttl = ttl
        self.protocol = 6  # TCP
        self.checksum = 0  # Initially 0
        self.source_ip = source_ip
        self.dest_ip = dest_ip

    def pack(self):
        header = struct.pack('!BBHHHBBH4s4s', 
                             (self.version << 4) + self.ihl, self.tos, 
                             self.total_length, self.id, 
                             self.frag_offset, self.ttl, 
                             self.protocol, self.checksum, 
                             socket.inet_aton(self.source_ip), 
                             socket.inet_aton(self.dest_ip))
        return header

    def calculate_checksum(self, header):
        if len(header) % 2 != 0:
            header += b'\0'
        checksum = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i + 1]
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF

    def set_checksum(self, header, payload):
        self.checksum = self.calculate_checksum(header)
        self.total_length = len(header) + len(payload)  # Set total length
        packed_header = self.pack()
        packed_header = packed_header[:10] + struct.pack('H', self.checksum) + packed_header[12:]
        return packed_header

def fragment_packet(ip_header, payload, max_size=1400):
    fragments = []
    total_len = len(payload)
    offset = 0
    fragment_id = ip_header.id

    while total_len > 0:
        # Fragment header
        frag_len = min(max_size, total_len)
        fragment = payload[offset:offset + frag_len]
        fragment_offset = offset // 8  # Fragment offset in 8-byte units

        ip_header.frag_offset = fragment_offset
        ip_header.total_length = frag_len + len(ip_header.pack())

        # Fragment head + payload
        fragment_header = ip_header.set_checksum(ip_header.pack())
        fragments.append(fragment_header + fragment)

        total_len -= frag_len
        offset += frag_len

    return fragments

def send_raw_packet(source_ip, dest_ip, payload):
    ip_header = IPHeader(source_ip, dest_ip)
    ip_header_data = ip_header.pack()

    # IP header checksum'ı hesapla
    packed_header = ip_header.set_checksum(ip_header_data)

    # Raw socket açılacak
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Paket gönderilecek
    sock.sendto(packed_header + payload, (dest_ip, 0))

    print("Paket gönderildi!")
