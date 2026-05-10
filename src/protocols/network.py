import socket


class IPv4:
    def __init__(self, pkg: bytes) -> None:
        # IPv4 header structure (all offsets in bytes):
        # [ Version+IHL (1B) ][ DSCP+ECN (1B) ][ Total Length (2B) ]
        # [ Identification (2B) ][ Flags+Fragment Offset (2B) ]
        # [ TTL (1B) ][ Protocol (1B) ][ Header Checksum (2B) ]
        # [ Src IP (4B) ][ Dst IP (4B) ][ Options (variable) ][ Payload ]

        # Version (upper nibble) and IHL (lower nibble) share byte 0
        self.version = (pkg[0] >> 4) & 0xF
        self.ihl = pkg[0] & 0xF  # IHL is in 32-bit words
        ihl_bytes = self.ihl * 4  # Actual header length in bytes

        self.dscp = (pkg[1] >> 2) & 0x3F
        self.ecn = pkg[1] & 0x3
        self.total_length = int.from_bytes(pkg[2:4], "big")
        self.identification = int.from_bytes(pkg[4:6], "big")

        # Flags (3 bits) and Fragment Offset (13 bits) share bytes 6-7
        flags_frag = int.from_bytes(pkg[6:8], "big")
        self.flags = (flags_frag >> 13) & 0x7  # Reserved, DF, MF
        self.fragment_offset = flags_frag & 0x1FFF

        self.ttl = pkg[8]
        self.protocol = pkg[9]
        self.header_checksum = int.from_bytes(pkg[10:12], "big")
        self.src_ip = pkg[12:16]
        self.dst_ip = pkg[16:20]

        # Options field present if IHL > 5 (i.e., header > 20 bytes)
        self.options = pkg[20:ihl_bytes] if self.ihl > 5 else None

        self.data = pkg[ihl_bytes:]

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntoa(ip)

    def __repr__(self) -> str:
        return (
            "--- IPv4 ".ljust(50, "-") + "\n"
            f"src         = {self.format_ip(self.src_ip)},\n"
            f"dst         = {self.format_ip(self.dst_ip)},\n"
            f"proto       = {self.protocol},\n"
            f"ttl         = {self.ttl},\n"
            f"flags       = {bin(self.flags)},\n"
            f"frag_offset = {self.fragment_offset}\n"
        )


class IPv6:
    def __init__(self, pkg: bytes) -> None:
        # IPv6 header structure (all offsets in bytes, fixed 40B header):
        # [ Version+TC+Flow Label (4B) ][ Payload Length (2B) ]
        # [ Next Header (1B) ][ Hop Limit (1B) ][ Src IP (16B) ][ Dst IP (16B) ]

        # Version (4b), Traffic Class (8b), Flow Label (20b) share first 4 bytes
        first_word = int.from_bytes(pkg[0:4], "big")
        self.version = (first_word >> 28) & 0xF
        self.traffic_class = (first_word >> 20) & 0xFF
        self.flow_label = first_word & 0xFFFFF

        self.payload_length = int.from_bytes(pkg[4:6], "big")
        self.next_header = pkg[6]
        self.hop_limit = pkg[7]
        self.src_ip = pkg[8:24]
        self.dst_ip = pkg[24:40]
        self.data = pkg[40:]

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntop(socket.AF_INET6, ip)

    def __repr__(self) -> str:
        return (
            "--- IPv6 ".ljust(50, "-") + "\n"
            f"src         = {self.format_ip(self.src_ip)},\n"
            f"dst         = {self.format_ip(self.dst_ip)},\n"
            f"next_header = {self.next_header},\n"
            f"hop_limit   = {self.hop_limit}\n"
        )
