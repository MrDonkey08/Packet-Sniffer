#!/usr/bin/env python3

from enum import IntEnum, Enum
from typing import Annotated
import typer
import socket

app = typer.Typer()


class EtherType(IntEnum):
    """IEEE 802.3 EtherType field values."""

    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


class Protocol(IntEnum):
    """IANA IP protocol numbers (IPv4 protocol / IPv6 next header)."""

    ICMPv4 = 1
    TCP = 6
    UDP = 17
    ICMPv6 = 58


class Port(IntEnum):
    """Transport layer port numbers — IANA."""

    # Well-known ports (0–1023)
    FTP_DATA = 20
    FTP = 21
    SSH = 22
    TELNET = 23
    SMTP = 25
    DNS = 53
    DHCP_SERVER = 67
    DHCP_CLIENT = 68
    TFTP = 69
    HTTP = 80
    POP2 = 109
    POP3 = 110
    NTP = 123
    IMAP = 143
    SNMP = 161
    SNMP_TRAP = 162
    LDAP = 389
    HTTPS = 443
    SMTPS = 465
    DHCP_V6_CLIENT = 546
    DHCP_V6_SERVER = 547
    SMTP_ALT = 587  # SMTP submission (RFC 6409)
    LDAPS = 636
    IMAPS = 993
    POP3S = 995

    # Registered ports (1024–49151)
    NFS = 2049


class EthernetFrame:
    def __init__(self, frame: bytes) -> None:
        # Ethernet II frame structure:
        # [ Dst MAC (6B) ][ Src MAC (6B) ][ EtherType (2B) ][ Payload ][ FCS (4B) ]
        self.dst_mac = frame[0:6]
        self.src_mac = frame[6:12]
        self.type = int.from_bytes(frame[12:14], "big")

        # 802.1Q VLAN tag (optional): EtherType 0x8100 means a 4B tag is inserted
        # before the real EtherType
        if self.type == 0x8100:
            self.vlan_tag = frame[14:16]  # PCP (3b), DEI (1b), VID (12b)
            self.type = int.from_bytes(frame[16:18], "big")
            self.data = frame[18:-4]
        else:
            self.vlan_tag = None
            self.data = frame[14:-4]  # Payload without FCS

        # FCS may not be present in captures (Wireshark often strips it)
        self.fcs = frame[-4:]

    def format_mac(self, mac: bytes) -> str:
        return mac.hex(":")

    def __repr__(self) -> str:
        return (
            "--- EthernetFrame ".ljust(50, "-") + "\n"
            f"src  = {self.format_mac(self.src_mac)},\n"
            f"dst  = {self.format_mac(self.dst_mac)},\n"
            f"type = {hex(self.type)},\n"
            f"vlan = {self.vlan_tag.hex() if self.vlan_tag else None}\n"
        )


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
        self.header_checksum = int.from_bytes(
            pkg[10:12], "big"
        )  # was a duplicate of protocol
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


class ARP:
    """ARP parser — RFC 826."""

    class HardwareType(IntEnum):
        ETHERNET = 1
        IEEE_802 = 6

    class Operation(IntEnum):
        REQUEST = 1
        REPLY = 2

    def __init__(self, segment: bytes) -> None:
        # ARP packet structure:
        # [ HTYPE (2B) ][ PTYPE (2B) ][ HLEN (1B) ][ PLEN (1B) ][ OPER (2B) ]
        # [ SHA (HLEN B) ][ SPA (PLEN B) ][ THA (HLEN B) ][ TPA (PLEN B) ]
        self.htype = int.from_bytes(segment[0:2], "big")  # hardware type
        self.ptype = int.from_bytes(
            segment[2:4], "big"
        )  # protocol type (same as EtherType)
        self.hlen = segment[4]  # hardware address length (e.g., 6 for MAC)
        self.plen = segment[5]  # protocol address length (e.g., 4 for IPv4)
        self.oper = int.from_bytes(segment[6:8], "big")  # operation (request/reply)

        # Sender and target addresses are variable length based on hlen/plen
        offset = 8
        self.sha = segment[offset : offset + self.hlen]
        offset += self.hlen  # sender hardware address
        self.spa = segment[offset : offset + self.plen]
        offset += self.plen  # sender protocol address
        self.tha = segment[offset : offset + self.hlen]
        offset += self.hlen  # target hardware address
        self.tpa = segment[offset : offset + self.plen]  # target protocol address

    def htype_name(self) -> str:
        try:
            return self.HardwareType(self.htype).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.htype})"

    def oper_name(self) -> str:
        try:
            return self.Operation(self.oper).name.title()
        except ValueError:
            return f"Unknown ({self.oper})"

    def format_mac(self, mac: bytes) -> str:
        return mac.hex(":")

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntoa(ip)

    def format_proto(self, addr: bytes) -> str:
        if self.ptype == EtherType.IPv4 and len(addr) == 4:
            return socket.inet_ntoa(addr)
        # Fallback for IPv6 or unknown protocol types
        if self.ptype == EtherType.IPv6 and len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
        return addr.hex(":")

    def __str__(self) -> str:
        return (
            "--- ARP ".ljust(50, "-") + "\n"
            f"htype      = {self.htype} ({self.htype_name()}),\n"
            f"ptype      = {hex(self.ptype)},\n"
            f"hlen       = {self.hlen},\n"
            f"plen       = {self.plen},\n"
            f"operation  = {self.oper} ({self.oper_name()}),\n"
            f"sender MAC = {self.format_mac(self.sha)},\n"
            f"sender IP  = {self.format_proto(self.spa)},\n"
            f"target MAC = {self.format_mac(self.tha)},\n"
            f"target IP  = {self.format_proto(self.tpa)}\n"
        )


class UDP:
    def __init__(self, datagram: bytes) -> None:
        # UDP header structure (8 bytes fixed):
        # [ Src Port (2B) ][ Dst Port (2B) ][ Length (2B) ][ Checksum (2B) ][ Payload ]
        self.src_port = int.from_bytes(datagram[0:2], "big")
        self.dst_port = int.from_bytes(datagram[2:4], "big")
        self.length = int.from_bytes(datagram[4:6], "big")  # header + payload length
        self.checksum = int.from_bytes(
            datagram[6:8], "big"
        )  # optional in IPv4, mandatory in IPv6
        self.data = datagram[8:]

    def __repr__(self) -> str:
        return (
            "--- UDP ".ljust(50, "-") + "\n"
            f"src_port = {self.src_port},\n"
            f"dst_port = {self.dst_port},\n"
            f"length   = {self.length},\n"
            f"checksum = {hex(self.checksum)}\n"
        )


class TCP:
    def __init__(self, segment: bytes) -> None:
        self.src_port = int.from_bytes(segment[0:2], "big")
        self.dst_port = int.from_bytes(segment[2:4], "big")
        self.seq_num = int.from_bytes(segment[4:8], "big")
        self.ack_num = int.from_bytes(segment[8:12], "big")

        # Data Offset (4b) and Reserved (3b) share byte 12 with NS flag (1b)
        self.data_offset = (segment[12] >> 4) & 0xF  # in 32-bit words
        header_length = self.data_offset * 4  # actual length in bytes

        # Flags spread across bytes 12-13:
        # byte 12: [Data Offset (4b)][Reserved (3b)][NS (1b)]
        # byte 13: [CWR][ECE][URG][ACK][PSH][RST][SYN][FIN]
        flags_word = int.from_bytes(segment[12:14], "big")
        self.flag_ns = bool(flags_word & 0x100)
        self.flag_cwr = bool(flags_word & 0x080)
        self.flag_ece = bool(flags_word & 0x040)
        self.flag_urg = bool(flags_word & 0x020)
        self.flag_ack = bool(flags_word & 0x010)
        self.flag_psh = bool(flags_word & 0x008)
        self.flag_rst = bool(flags_word & 0x004)
        self.flag_syn = bool(flags_word & 0x002)
        self.flag_fin = bool(flags_word & 0x001)

        self.window_size = int.from_bytes(segment[14:16], "big")
        self.checksum = int.from_bytes(segment[16:18], "big")
        self.urgent_pointer = int.from_bytes(
            segment[18:20], "big"
        )  # only meaningful if URG is set

        # Options present if data_offset > 5 (i.e., header > 20 bytes)
        self.options = segment[20:header_length] if self.data_offset > 5 else None

        self.data = segment[header_length:]

    def flag_str(self) -> str:
        names = ["NS", "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"]
        values = [
            self.flag_ns,
            self.flag_cwr,
            self.flag_ece,
            self.flag_urg,
            self.flag_ack,
            self.flag_psh,
            self.flag_rst,
            self.flag_syn,
            self.flag_fin,
        ]
        active = [name for name, val in zip(names, values) if val]
        return ", ".join(active) if active else "None"

    def __str__(self) -> str:
        return (
            "--- TCP ".ljust(50, "-") + "\n"
            f"src_port    = {self.src_port},\n"
            f"dst_port    = {self.dst_port},\n"
            f"seq_num     = {self.seq_num},\n"
            f"ack_num     = {self.ack_num},\n"
            f"data_offset = {self.data_offset} ({self.data_offset * 4} bytes),\n"
            f"flags       = {self.flag_str()},\n"
            f"window_size = {self.window_size},\n"
            f"checksum    = {hex(self.checksum)},\n"
            f"urgent_ptr  = {self.urgent_pointer},\n"
            f"options     = {self.options.hex() if self.options else None}\n"
        )


class ICMPv4:
    # Type constants
    class Type(IntEnum):
        ECHO_REPLY = 0
        DEST_UNREACHABLE = 3
        REDIRECT = 5
        ECHO_REQUEST = 8
        TIME_EXCEEDED = 11
        PARAMETER_PROBLEM = 12
        TIMESTAMP_REQUEST = 13
        TIMESTAMP_REPLY = 14

    # Destination Unreachable codes (Type 3)
    class CodeDestUnreachable(IntEnum):
        NET_UNREACHABLE = 0
        HOST_UNREACHABLE = 1
        PROTO_UNREACHABLE = 2
        PORT_UNREACHABLE = 3
        FRAGMENTATION_NEEDED = 4
        SOURCE_ROUTE_FAILED = 5

    # Time Exceeded codes (Type 11)
    class CodeTimeExceeded(IntEnum):
        TTL_EXCEEDED = 0
        FRAGMENT_REASSEMBLY = 1

    # Redirect codes (Type 5)
    class CodeRedirect(IntEnum):
        REDIRECT_NET = 0
        REDIRECT_HOST = 1
        REDIRECT_TOS_NET = 2
        REDIRECT_TOS_HOST = 3

    def __init__(self, segment: bytes) -> None:
        # ICMPv4 base header structure (8 bytes fixed):
        # [ Type (1B) ][ Code (1B) ][ Checksum (2B) ][ Rest of Header (4B) ]
        # "Rest of Header" is type-dependent
        self.type = segment[0]
        self.code = segment[1]
        self.checksum = int.from_bytes(segment[2:4], "big")

        # Bytes 4-7 are type-dependent
        rest = segment[4:8]

        # Type-specific fields
        if self.type in (self.Type.ECHO_REQUEST, self.Type.ECHO_REPLY):
            # [ Identifier (2B) ][ Sequence Number (2B) ]
            self.identifier = int.from_bytes(rest[0:2], "big")
            self.sequence_num = int.from_bytes(rest[2:4], "big")

        elif self.type == self.Type.DEST_UNREACHABLE:
            # [ Unused (2B) ][ Next-Hop MTU (2B) ] (RFC 1191)
            self.next_hop_mtu = int.from_bytes(rest[2:4], "big")

        elif self.type == self.Type.REDIRECT:
            # [ Gateway IP (4B) ]
            self.gateway_ip = rest[0:4]

        elif (
            self.type == self.Type.TIMESTAMP_REQUEST
            or self.type == self.Type.TIMESTAMP_REPLY
        ):
            # [ Identifier (2B) ][ Sequence Number (2B) ]
            # Followed by Originate, Receive, Transmit timestamps (4B each)
            self.identifier = int.from_bytes(rest[0:2], "big")
            self.sequence_num = int.from_bytes(rest[2:4], "big")
            self.originate_ts = int.from_bytes(segment[8:12], "big")
            self.receive_ts = int.from_bytes(segment[12:16], "big")
            self.transmit_ts = int.from_bytes(segment[16:20], "big")

        # Original IP header + first 8 bytes of original datagram
        # present in error messages (Type 3, 5, 11, 12)
        if self.type in (
            self.Type.DEST_UNREACHABLE,
            self.Type.REDIRECT,
            self.Type.TIME_EXCEEDED,
            self.Type.PARAMETER_PROBLEM,
        ):
            self.original_datagram = segment[8:]
        else:
            self.original_datagram = None

        self.data = segment[8:]

    def type_name(self) -> str:
        try:
            return self.Type(self.type).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.type})"

    def code_name(self) -> str:
        try:
            if self.type == self.Type.DEST_UNREACHABLE:
                return (
                    self.CodeDestUnreachable(self.code).name.replace("_", " ").title()
                )
            elif self.type == self.Type.TIME_EXCEEDED:
                return self.CodeTimeExceeded(self.code).name.replace("_", " ").title()
            elif self.type == self.Type.REDIRECT:
                return self.CodeRedirect(self.code).name.replace("_", " ").title()
            return str(self.code)
        except ValueError:
            return f"Unknown ({self.code})"

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntoa(ip)

    def __str__(self) -> str:
        lines = [
            "--- ICMPv4 ".ljust(50, "-"),
            f"type          = {self.type} ({self.type_name()}),",
            f"code          = {self.code} ({self.code_name()}),",
            f"checksum      = {hex(self.checksum)},",
        ]

        # Type-specific fields
        if self.type in (self.Type.ECHO_REQUEST, self.Type.ECHO_REPLY):
            lines += [
                f"identifier    = {self.identifier},",
                f"sequence_num  = {self.sequence_num},",
            ]
        elif self.type == self.Type.DEST_UNREACHABLE:
            lines.append(f"next_hop_mtu  = {self.next_hop_mtu},")
        elif self.type == self.Type.REDIRECT:
            lines.append(f"gateway_ip    = {self.format_ip(self.gateway_ip)},")
        elif self.type in (self.Type.TIMESTAMP_REQUEST, self.Type.TIMESTAMP_REPLY):
            lines += [
                f"identifier    = {self.identifier},",
                f"sequence_num  = {self.sequence_num},",
                f"originate_ts  = {self.originate_ts},",
                f"receive_ts    = {self.receive_ts},",
                f"transmit_ts   = {self.transmit_ts},",
            ]

        if self.original_datagram:
            lines.append(f"original_dgram= {self.original_datagram[:8].hex()} ...,")

        return "\n".join(lines) + "\n"


class ICMPv6:
    """ICMPv6 parser — RFC 4443 (base) + RFC 4861 (NDP)."""

    class Type(IntEnum):
        # Error messages (0-127)
        DEST_UNREACHABLE = 1
        PACKET_TOO_BIG = 2
        TIME_EXCEEDED = 3
        PARAMETER_PROBLEM = 4
        # Informational messages (128-255)
        ECHO_REQUEST = 128
        ECHO_REPLY = 129
        # Neighbor Discovery Protocol — RFC 4861
        ROUTER_SOLICITATION = 133
        ROUTER_ADVERTISEMENT = 134
        NEIGHBOR_SOLICITATION = 135
        NEIGHBOR_ADVERTISEMENT = 136
        REDIRECT = 137

    class CodeDestUnreachable(IntEnum):
        NO_ROUTE = 0
        ADMIN_PROHIBITED = 1
        BEYOND_SCOPE = 2
        ADDRESS_UNREACHABLE = 3
        PORT_UNREACHABLE = 4
        POLICY_FAIL = 5
        REJECT_ROUTE = 6

    class CodeTimeExceeded(IntEnum):
        HOP_LIMIT_EXCEEDED = 0
        FRAGMENT_REASSEMBLY = 1

    class CodeParameterProblem(IntEnum):
        ERRONEOUS_HEADER = 0
        UNKNOWN_NEXT_HEADER = 1
        UNKNOWN_OPTION = 2

    def __init__(self, segment: bytes) -> None:
        # ICMPv6 base header structure (8 bytes fixed):
        # [ Type (1B) ][ Code (1B) ][ Checksum (2B) ][ Rest of Header (4B) ]
        self.type = segment[0]
        self.code = segment[1]
        self.checksum = int.from_bytes(segment[2:4], "big")

        rest = segment[4:8]

        # Error messages — carry the original invoking packet after byte 8
        self.original_datagram = None

        if self.type == self.Type.DEST_UNREACHABLE:
            # [ Unused (4B) ]
            pass

        elif self.type == self.Type.PACKET_TOO_BIG:
            # [ MTU (4B) ]
            self.mtu = int.from_bytes(rest[0:4], "big")

        elif self.type == self.Type.TIME_EXCEEDED:
            # [ Unused (4B) ]
            pass

        elif self.type == self.Type.PARAMETER_PROBLEM:
            # [ Pointer (4B) ] — byte offset of the offending field
            self.pointer = int.from_bytes(rest[0:4], "big")

        elif self.type in (self.Type.ECHO_REQUEST, self.Type.ECHO_REPLY):
            # [ Identifier (2B) ][ Sequence Number (2B) ]
            self.identifier = int.from_bytes(rest[0:2], "big")
            self.sequence_num = int.from_bytes(rest[2:4], "big")

        elif self.type == self.Type.ROUTER_SOLICITATION:
            # [ Reserved (4B) ][ Options (variable) ]
            self.ndp_options = segment[8:]

        elif self.type == self.Type.ROUTER_ADVERTISEMENT:
            # [ Cur Hop Limit (1B) ][ Flags (1B) ][ Router Lifetime (2B) ]
            # [ Reachable Time (4B) ][ Retrans Timer (4B) ][ Options (variable) ]
            self.cur_hop_limit = rest[0]
            ra_flags = rest[1]
            self.ra_flag_managed = bool(ra_flags & 0x80)  # M bit
            self.ra_flag_other = bool(ra_flags & 0x40)  # O bit
            self.router_lifetime = int.from_bytes(rest[2:4], "big")
            self.reachable_time = int.from_bytes(segment[8:12], "big")
            self.retrans_timer = int.from_bytes(segment[12:16], "big")
            self.ndp_options = segment[16:]

        elif self.type == self.Type.NEIGHBOR_SOLICITATION:
            # [ Reserved (4B) ][ Target Address (16B) ][ Options (variable) ]
            self.target_addr = segment[8:24]
            self.ndp_options = segment[24:]

        elif self.type == self.Type.NEIGHBOR_ADVERTISEMENT:
            # [ Flags (4B) ][ Target Address (16B) ][ Options (variable) ]
            na_flags = int.from_bytes(rest[0:4], "big")
            self.na_flag_router = bool(na_flags & 0x80000000)  # R bit
            self.na_flag_solicited = bool(na_flags & 0x40000000)  # S bit
            self.na_flag_override = bool(na_flags & 0x20000000)  # O bit
            self.target_addr = segment[8:24]
            self.ndp_options = segment[24:]

        elif self.type == self.Type.REDIRECT:
            # [ Reserved (4B) ][ Target Address (16B) ][ Dest Address (16B) ][ Options ]
            self.target_addr = segment[8:24]
            self.dest_addr = segment[24:40]
            self.ndp_options = segment[40:]

        # All error messages (Type 1-4) carry the invoking packet after byte 8
        if 1 <= self.type <= 4:
            self.original_datagram = segment[8:]

        self.data = segment[8:]

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntop(socket.AF_INET6, ip)

    def type_name(self) -> str:
        try:
            return self.Type(self.type).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.type})"

    def code_name(self) -> str:
        try:
            if self.type == self.Type.DEST_UNREACHABLE:
                return (
                    self.CodeDestUnreachable(self.code).name.replace("_", " ").title()
                )
            elif self.type == self.Type.TIME_EXCEEDED:
                return self.CodeTimeExceeded(self.code).name.replace("_", " ").title()
            elif self.type == self.Type.PARAMETER_PROBLEM:
                return (
                    self.CodeParameterProblem(self.code).name.replace("_", " ").title()
                )
            return str(self.code)
        except ValueError:
            return f"Unknown ({self.code})"

    def __str__(self) -> str:
        lines = [
            "--- ICMPv6 ".ljust(50, "-"),
            f"type          = {self.type} ({self.type_name()}),",
            f"code          = {self.code} ({self.code_name()}),",
            f"checksum      = {hex(self.checksum)},",
        ]

        if self.type == self.Type.PACKET_TOO_BIG:
            lines.append(f"mtu           = {self.mtu},")

        elif self.type == self.Type.PARAMETER_PROBLEM:
            lines.append(f"pointer       = {self.pointer},")

        elif self.type in (self.Type.ECHO_REQUEST, self.Type.ECHO_REPLY):
            lines += [
                f"identifier    = {self.identifier},",
                f"sequence_num  = {self.sequence_num},",
            ]

        elif self.type == self.Type.ROUTER_ADVERTISEMENT:
            lines += [
                f"cur_hop_limit = {self.cur_hop_limit},",
                f"flag_managed  = {self.ra_flag_managed},",
                f"flag_other    = {self.ra_flag_other},",
                f"router_lifetime = {self.router_lifetime},",
                f"reachable_time  = {self.reachable_time},",
                f"retrans_timer   = {self.retrans_timer},",
            ]

        elif self.type in (
            self.Type.NEIGHBOR_SOLICITATION,
            self.Type.NEIGHBOR_ADVERTISEMENT,
        ):
            lines.append(f"target_addr   = {self.format_ip(self.target_addr)},")
            if self.type == self.Type.NEIGHBOR_ADVERTISEMENT:
                lines += [
                    f"flag_router   = {self.na_flag_router},",
                    f"flag_solicited= {self.na_flag_solicited},",
                    f"flag_override = {self.na_flag_override},",
                ]

        elif self.type == self.Type.REDIRECT:
            lines += [
                f"target_addr   = {self.format_ip(self.target_addr)},",
                f"dest_addr     = {self.format_ip(self.dest_addr)},",
            ]

        if self.original_datagram:
            lines.append(f"original_dgram= {self.original_datagram[:8].hex()} ...,")

        return "\n".join(lines) + "\n"


class DNS:
    """DNS parser — RFC 1035."""

    class QType(IntEnum):
        A = 1
        NS = 2
        CNAME = 5
        SOA = 6
        PTR = 12
        MX = 15
        AAAA = 28
        TXT = 16
        SRV = 33
        ANY = 255

    class QClass(IntEnum):
        IN = 1  # Internet
        CS = 2  # CSNET
        CH = 3  # CHAOS
        HS = 4  # Hesiod
        ANY = 255

    class RCode(IntEnum):
        NO_ERROR = 0
        FORMAT_ERROR = 1
        SERVER_FAIL = 2
        NAME_ERROR = 3  # NXDOMAIN
        NOT_IMPLEMENTED = 4
        REFUSED = 5

    def __init__(self, data: bytes) -> None:
        # DNS header structure (12 bytes fixed):
        # [ ID (2B) ][ Flags (2B) ][ QDCOUNT (2B) ][ ANCOUNT (2B) ]
        # [ NSCOUNT (2B) ][ ARCOUNT (2B) ]
        self.id = int.from_bytes(data[0:2], "big")

        # Flags word:
        # [ QR (1b) ][ Opcode (4b) ][ AA (1b) ][ TC (1b) ][ RD (1b) ]
        # [ RA (1b) ][ Z (1b) ][ AD (1b) ][ CD (1b) ][ RCODE (4b) ]
        flags = int.from_bytes(data[2:4], "big")
        self.qr = bool((flags >> 15) & 0x1)  # 0 = query, 1 = response
        self.opcode = (flags >> 11) & 0xF
        self.flag_aa = bool((flags >> 10) & 0x1)  # authoritative answer
        self.flag_tc = bool((flags >> 9) & 0x1)  # truncated
        self.flag_rd = bool((flags >> 8) & 0x1)  # recursion desired
        self.flag_ra = bool((flags >> 7) & 0x1)  # recursion available
        self.flag_ad = bool((flags >> 5) & 0x1)  # authentic data (DNSSEC)
        self.flag_cd = bool((flags >> 4) & 0x1)  # checking disabled (DNSSEC)
        self.rcode = flags & 0xF

        self.qdcount = int.from_bytes(data[4:6], "big")  # question count
        self.ancount = int.from_bytes(data[6:8], "big")  # answer count
        self.nscount = int.from_bytes(data[8:10], "big")  # authority count
        self.arcount = int.from_bytes(data[10:12], "big")  # additional count

        # Parse sections
        offset = 12
        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

        for _ in range(self.qdcount):
            q, offset = self._parse_question(data, offset)
            self.questions.append(q)

        for _ in range(self.ancount):
            rr, offset = self._parse_rr(data, offset)
            self.answers.append(rr)

        for _ in range(self.nscount):
            rr, offset = self._parse_rr(data, offset)
            self.authorities.append(rr)

        for _ in range(self.arcount):
            rr, offset = self._parse_rr(data, offset)
            self.additionals.append(rr)

    def _parse_name(self, data: bytes, offset: int) -> tuple[str, int]:
        """
        Parse a DNS name at the given offset, following compression pointers
        (RFC 1035 section 4.1.4). Returns the name and the offset just after
        the name field (not after any pointer target).
        """
        labels = []
        visited = set()  # guard against pointer loops
        end_offset = None  # offset to return — set on first pointer jump

        while True:
            if offset in visited:
                raise ValueError(f"DNS name compression loop at offset {offset}")
            visited.add(offset)

            length = data[offset]

            if length == 0:
                # End of name
                offset += 1
                break

            elif (length & 0xC0) == 0xC0:
                # Compression pointer (2 bytes): upper 2 bits are 11
                if end_offset is None:
                    end_offset = offset + 2  # caller resumes after the pointer
                pointer = int.from_bytes(data[offset : offset + 2], "big") & 0x3FFF
                offset = pointer

            else:
                # Regular label
                offset += 1
                labels.append(
                    data[offset : offset + length].decode("ascii", errors="replace")
                )
                offset += length

        return ".".join(labels), (end_offset if end_offset is not None else offset)

    def _parse_question(self, data: bytes, offset: int) -> tuple[dict, int]:
        """Parse a DNS question entry."""
        name, offset = self._parse_name(data, offset)
        qtype = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        qclass = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        return {"name": name, "qtype": qtype, "qclass": qclass}, offset

    def _parse_rr(self, data: bytes, offset: int) -> tuple[dict, int]:
        """Parse a DNS resource record."""
        name, offset = self._parse_name(data, offset)
        rtype = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        rclass = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        ttl = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        rdlength = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        rdata = data[offset : offset + rdlength]
        offset += rdlength

        # Decode rdata based on type
        rdata_decoded = self._decode_rdata(data, rtype, rdata, offset - rdlength)

        return {
            "name": name,
            "rtype": rtype,
            "rclass": rclass,
            "ttl": ttl,
            "rdata": rdata_decoded,
        }, offset

    def _decode_rdata(self, data: bytes, rtype: int, rdata: bytes, offset: int) -> str:
        """Decode rdata field into a human-readable string."""
        try:
            if rtype == self.QType.A:
                return socket.inet_ntoa(rdata)

            elif rtype == self.QType.AAAA:
                return socket.inet_ntop(socket.AF_INET6, rdata)

            elif rtype in (self.QType.NS, self.QType.CNAME, self.QType.PTR):
                name, _ = self._parse_name(data, offset)
                return name

            elif rtype == self.QType.MX:
                preference = int.from_bytes(rdata[0:2], "big")
                exchange, _ = self._parse_name(data, offset + 2)
                return f"{preference} {exchange}"

            elif rtype == self.QType.TXT:
                # TXT rdata: [ length (1B) ][ string ]... (may be multiple strings)
                strings = []
                i = 0
                while i < len(rdata):
                    slen = rdata[i]
                    i += 1
                    strings.append(
                        rdata[i : i + slen].decode("utf-8", errors="replace")
                    )
                    i += slen
                return " | ".join(strings)

            elif rtype == self.QType.SOA:
                # [ MNAME ][ RNAME ][ Serial (4B) ][ Refresh (4B) ]
                # [ Retry (4B) ][ Expire (4B) ][ Minimum (4B) ]
                mname, off = self._parse_name(data, offset)
                rname, off = self._parse_name(data, off)
                serial = int.from_bytes(data[off : off + 4], "big")
                return f"mname={mname} rname={rname} serial={serial}"

            elif rtype == self.QType.SRV:
                # [ Priority (2B) ][ Weight (2B) ][ Port (2B) ][ Target ]
                priority = int.from_bytes(rdata[0:2], "big")
                weight = int.from_bytes(rdata[2:4], "big")
                port = int.from_bytes(rdata[4:6], "big")
                target, _ = self._parse_name(data, offset + 6)
                return f"{priority} {weight} {port} {target}"

        except Exception:
            pass

        return rdata.hex()  # fallback for unknown/malformed rdata

    def qtype_name(self, qtype: int) -> str:
        try:
            return self.QType(qtype).name
        except ValueError:
            return str(qtype)

    def qclass_name(self, qclass: int) -> str:
        try:
            return self.QClass(qclass).name
        except ValueError:
            return str(qclass)

    def rcode_name(self) -> str:
        try:
            return self.RCode(self.rcode).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.rcode})"

    def _fmt_section(self, records: list[dict], label: str) -> list[str]:
        if not records:
            return []
        lines = [f"\n  {label}:"]
        for rr in records:
            lines.append(
                f"    {rr['name']:<30} "
                f"{rr['ttl']:<8} "
                f"{self.qclass_name(rr['rclass']):<6} "
                f"{self.qtype_name(rr['rtype']):<8} "
                f"{rr['rdata']}"
            )
        return lines

    def __str__(self) -> str:
        lines = [
            "--- DNS ".ljust(50, "-"),
            f"id          = {hex(self.id)},",
            f"type        = {'Response' if self.qr else 'Query'},",
            f"opcode      = {self.opcode},",
            f"rcode       = {self.rcode} ({self.rcode_name()}),",
            f"flags       = "
            f"{'AA ' if self.flag_aa else ''}"
            f"{'TC ' if self.flag_tc else ''}"
            f"{'RD ' if self.flag_rd else ''}"
            f"{'RA ' if self.flag_ra else ''}"
            f"{'AD ' if self.flag_ad else ''}"
            f"{'CD ' if self.flag_cd else ''}".strip() + ",",
            f"questions   = {self.qdcount},",
            f"answers     = {self.ancount},",
            f"authorities = {self.nscount},",
            f"additionals = {self.arcount},",
        ]

        # Questions section
        if self.questions:
            lines.append("\n  Questions:")
            for q in self.questions:
                lines.append(
                    f"    {q['name']:<30} "
                    f"{self.qclass_name(q['qclass']):<6} "
                    f"{self.qtype_name(q['qtype'])}"
                )

        lines += self._fmt_section(self.answers, "Answers")
        lines += self._fmt_section(self.authorities, "Authorities")
        lines += self._fmt_section(self.additionals, "Additionals")

        return "\n".join(lines) + "\n"


class DHCPv4:
    """DHCPv4 parser — RFC 2131 / RFC 2132."""

    class MessageType(IntEnum):
        DISCOVER = 1
        OFFER = 2
        REQUEST = 3
        DECLINE = 4
        ACK = 5
        NAK = 6
        RELEASE = 7
        INFORM = 8

    class OpCode(IntEnum):
        REQUEST = 1  # client -> server
        REPLY = 2  # server -> client

    class HardwareType(IntEnum):
        ETHERNET = 1
        IEEE_802 = 6
        ARCNET = 7
        LOCALTALK = 11
        LOCALNET = 12
        SMDS = 14
        FRAME_RELAY = 15
        ATM = 16
        HDLC = 17
        FIBRE_CHANNEL = 18
        ATM_2 = 19
        SERIAL = 20

    # DHCP option codes — RFC 2132
    class Option(IntEnum):
        SUBNET_MASK = 1
        ROUTER = 3
        DNS_SERVER = 6
        HOST_NAME = 12
        DOMAIN_NAME = 15
        BROADCAST_ADDR = 28
        REQUESTED_IP = 50
        LEASE_TIME = 51
        MSG_TYPE = 53
        SERVER_ID = 54
        PARAM_REQUEST_LIST = 55
        MAX_MSG_SIZE = 57
        RENEWAL_TIME = 58
        REBINDING_TIME = 59
        VENDOR_CLASS_ID = 60
        CLIENT_ID = 61
        DOMAIN_SEARCH = 119
        CLASSLESS_ROUTE = 121
        END = 255

    # Magic cookie that marks the start of DHCP options (RFC 2131)
    MAGIC_COOKIE = b"\x63\x82\x53\x63"

    def __init__(self, data: bytes) -> None:
        # DHCPv4 base header structure (236 bytes fixed):
        # [ Op (1B) ][ HType (1B) ][ HLen (1B) ][ Hops (1B) ]
        # [ XID (4B) ][ Secs (2B) ][ Flags (2B) ]
        # [ CIAddr (4B) ][ YIAddr (4B) ][ SIAddr (4B) ][ GIAddr (4B) ]
        # [ CHAddr (16B) ][ SName (64B) ][ File (128B) ]
        # [ Magic Cookie (4B) ][ Options (variable) ]
        self.op = data[0]
        self.htype = data[1]
        self.hlen = data[2]  # hardware address length
        self.hops = data[3]

        self.xid = int.from_bytes(data[4:8], "big")  # transaction ID
        self.secs = int.from_bytes(data[8:10], "big")  # seconds since start
        flags = int.from_bytes(data[10:12], "big")
        self.flag_broadcast = bool((flags >> 15) & 0x1)  # broadcast flag

        self.ciaddr = data[12:16]  # client IP (if already has one)
        self.yiaddr = data[16:20]  # your IP (offered/assigned by server)
        self.siaddr = data[20:24]  # next server IP (e.g., for TFTP boot)
        self.giaddr = data[24:28]  # relay agent IP

        # CHAddr is fixed 16B but only hlen bytes are meaningful
        self.chaddr = data[28 : 28 + self.hlen]

        self.sname = (
            data[44:108].rstrip(b"\x00").decode("ascii", errors="replace")
        )  # server name
        self.file = (
            data[108:236].rstrip(b"\x00").decode("ascii", errors="replace")
        )  # boot file

        # Options — must start with magic cookie
        self.options: dict[int, object] = {}
        if data[236:240] == self.MAGIC_COOKIE:
            self.options = self._parse_options(data[240:])

    def _parse_options(self, data: bytes) -> dict[int, object]:
        """Parse DHCP options TLV encoding — RFC 2132."""
        options = {}
        i = 0
        while i < len(data):
            code = data[i]
            i += 1

            if code == 0:  # Pad option — no length byte
                continue
            if code == 255:  # End option — stop parsing
                break

            length = data[i]
            i += 1
            value = data[i : i + length]
            i += length

            options[code] = self._decode_option(code, value)

        return options

    def _decode_option(self, code: int, value: bytes) -> object:
        """Decode a DHCP option value into a human-readable form."""
        try:
            opt = self.Option(code)

            if opt == self.Option.MSG_TYPE:
                return self.MessageType(value[0]).name.replace("_", " ").title()

            elif opt in (
                self.Option.SUBNET_MASK,
                self.Option.ROUTER,
                self.Option.DNS_SERVER,
                self.Option.BROADCAST_ADDR,
                self.Option.REQUESTED_IP,
                self.Option.SERVER_ID,
            ):
                # One or more IPv4 addresses (4B each)
                addrs = [
                    socket.inet_ntoa(value[j : j + 4]) for j in range(0, len(value), 4)
                ]
                return ", ".join(addrs)

            elif opt in (
                self.Option.LEASE_TIME,
                self.Option.RENEWAL_TIME,
                self.Option.REBINDING_TIME,
            ):
                return f"{int.from_bytes(value, 'big')}s"

            elif opt == self.Option.MAX_MSG_SIZE:
                return str(int.from_bytes(value, "big"))

            elif opt in (
                self.Option.HOST_NAME,
                self.Option.DOMAIN_NAME,
                self.Option.VENDOR_CLASS_ID,
            ):
                return value.decode("ascii", errors="replace")

            elif opt == self.Option.CLIENT_ID:
                # [ HType (1B) ][ Client Hardware Address ]
                htype = value[0]
                addr = value[1:]
                return f"htype={htype} addr={addr.hex(':')}"

            elif opt == self.Option.PARAM_REQUEST_LIST:
                # List of requested option codes
                names = []
                for code in value:
                    try:
                        names.append(self.Option(code).name)
                    except ValueError:
                        names.append(str(code))
                return ", ".join(names)

            elif opt == self.Option.CLASSLESS_ROUTE:
                # [ Mask Length (1B) ][ Significant Octets ][ Router (4B) ]
                routes = []
                j = 0
                while j < len(value):
                    mask_len = value[j]
                    j += 1
                    sig_bytes = (mask_len + 7) // 8
                    network = value[j : j + sig_bytes].ljust(4, b"\x00")
                    j += sig_bytes
                    router = socket.inet_ntoa(value[j : j + 4])
                    j += 4
                    routes.append(
                        f"{socket.inet_ntoa(network)}/{mask_len} via {router}"
                    )
                return ", ".join(routes)

        except ValueError, IndexError:
            pass

        return value.hex()  # fallback for unknown/malformed options

    def op_name(self) -> str:
        try:
            return self.OpCode(self.op).name.title()
        except ValueError:
            return f"Unknown ({self.op})"

    def htype_name(self) -> str:
        try:
            return self.HardwareType(self.htype).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.htype})"

    def format_ip(self, ip: bytes) -> str:
        return socket.inet_ntoa(ip)

    def format_mac(self, mac: bytes) -> str:
        return mac.hex(":")

    def __str__(self) -> str:
        lines = [
            "--- DHCPv4 ".ljust(50, "-"),
            f"op             = {self.op} ({self.op_name()}),",
            f"htype          = {self.htype} ({self.htype_name()}),",
            f"hlen           = {self.hlen},",
            f"hops           = {self.hops},",
            f"xid            = {hex(self.xid)},",
            f"secs           = {self.secs},",
            f"flag_broadcast = {self.flag_broadcast},",
            f"ciaddr         = {self.format_ip(self.ciaddr)},",
            f"yiaddr         = {self.format_ip(self.yiaddr)},",
            f"siaddr         = {self.format_ip(self.siaddr)},",
            f"giaddr         = {self.format_ip(self.giaddr)},",
            f"chaddr         = {self.format_mac(self.chaddr)},",
        ]

        if self.sname:
            lines.append(f"sname         = {self.sname},")
        if self.file:
            lines.append(f"file          = {self.file},")

        if self.options:
            lines.append("\n  Options:")
            for code, value in self.options.items():
                try:
                    name = self.Option(code).name
                except ValueError:
                    name = f"Option({code})"
                lines.append(f"    {name:<24} {value}")

        return "\n".join(lines) + "\n"


class DHCPv6:
    """DHCPv6 parser — RFC 8415."""

    class MessageType(IntEnum):
        SOLICIT = 1
        ADVERTISE = 2
        REQUEST = 3
        CONFIRM = 4
        RENEW = 5
        REBIND = 6
        REPLY = 7
        RELEASE = 8
        DECLINE = 9
        RECONFIGURE = 10
        INFO_REQUEST = 11
        RELAY_FORW = 12
        RELAY_REPL = 13

    class OptionCode(IntEnum):
        CLIENT_ID = 1
        SERVER_ID = 2
        IA_NA = 3  # Identity Association for Non-temporary Addresses
        IA_TA = 4  # Identity Association for Temporary Addresses
        IA_ADDR = 5
        ORO = 6  # Option Request Option
        PREFERENCE = 7
        ELAPSED_TIME = 8
        RELAY_MSG = 9
        AUTH = 11
        UNICAST = 12
        STATUS_CODE = 13
        RAPID_COMMIT = 14
        USER_CLASS = 15
        VENDOR_CLASS = 16
        VENDOR_OPTS = 17
        INTERFACE_ID = 18
        RECONF_MSG = 19
        RECONF_ACCEPT = 20
        DNS_SERVERS = 23  # RFC 3646
        DOMAIN_LIST = 24  # RFC 3646
        IA_PD = 25  # RFC 3633 — Prefix Delegation
        IA_PREFIX = 26  # RFC 3633
        NTP_SERVER = 56  # RFC 5908
        BOOTFILE_URL = 59  # RFC 5970
        BOOTFILE_PARAM = 60  # RFC 5970
        CLIENT_ARCH_TYPE = 61  # RFC 5970
        NII = 62  # RFC 5970
        FQDN = 72  # RFC 4704
        SOL_MAX_RT = 82  # RFC 7083
        INF_MAX_RT = 83  # RFC 7083

    class StatusCode(IntEnum):
        SUCCESS = 0
        UNSPEC_FAIL = 1
        NO_ADDRS_AVAIL = 2
        NO_BINDING = 3
        NOT_ON_LINK = 4
        USE_MULTICAST = 5
        NO_PREFIX_AVAIL = 6

    class DUIDType(IntEnum):
        LLT = 1  # Link-layer address + time
        EN = 2  # Enterprise number
        LL = 3  # Link-layer address
        UUID = 4  # RFC 6355

    def __init__(self, data: bytes) -> None:
        self.msg_type = data[0]

        # Relay messages (RELAY_FORW/RELAY_REPL) have a different structure:
        # [ Msg Type (1B) ][ Hop Count (1B) ][ Link Address (16B) ][ Peer Address (16B) ]
        # [ Options (variable) ]
        if self.msg_type in (self.MessageType.RELAY_FORW, self.MessageType.RELAY_REPL):
            self.hop_count = data[1]
            self.link_address = data[2:18]
            self.peer_address = data[18:34]
            self.options = self._parse_options(data[34:])
            self.xid = None

        # Regular messages:
        # [ Msg Type (1B) ][ Transaction ID (3B) ][ Options (variable) ]
        else:
            self.hop_count = None
            self.link_address = None
            self.peer_address = None
            self.xid = int.from_bytes(data[1:4], "big")
            self.options = self._parse_options(data[4:])

    def _parse_options(self, data: bytes) -> dict[int, object]:
        """Parse DHCPv6 options — RFC 8415 section 21.
        All options use:  [ Code (2B) ][ Length (2B) ][ Value (Length B) ]
        """
        options = {}
        i = 0
        while i + 4 <= len(data):
            code = int.from_bytes(data[i : i + 2], "big")
            i += 2
            length = int.from_bytes(data[i : i + 2], "big")
            i += 2
            value = data[i : i + length]
            i += length
            options[code] = self._decode_option(code, value, data)
        return options

    def _decode_duid(self, data: bytes) -> str:
        """Decode a DUID (DHCP Unique Identifier) — RFC 8415 section 11."""
        if len(data) < 2:
            return data.hex()
        duid_type = int.from_bytes(data[0:2], "big")
        try:
            dtype = self.DUIDType(duid_type)
            if dtype == self.DUIDType.LLT:
                # [ Type (2B) ][ HW Type (2B) ][ Time (4B) ][ LL Addr (variable) ]
                hw_type = int.from_bytes(data[2:4], "big")
                time = int.from_bytes(data[4:8], "big")
                ll_addr = data[8:].hex(":")
                return f"LLT hw_type={hw_type} time={time} addr={ll_addr}"
            elif dtype == self.DUIDType.EN:
                # [ Type (2B) ][ Enterprise Number (4B) ][ Identifier (variable) ]
                en = int.from_bytes(data[2:6], "big")
                uid = data[6:].hex()
                return f"EN enterprise={en} id={uid}"
            elif dtype == self.DUIDType.LL:
                # [ Type (2B) ][ HW Type (2B) ][ LL Addr (variable) ]
                hw_type = int.from_bytes(data[2:4], "big")
                ll_addr = data[4:].hex(":")
                return f"LL hw_type={hw_type} addr={ll_addr}"
            elif dtype == self.DUIDType.UUID:
                return f"UUID {data[2:].hex()}"
        except ValueError:
            pass
        return data.hex()

    def _decode_option(self, code: int, value: bytes, full_data: bytes) -> object:
        """Decode a DHCPv6 option value into a human-readable form."""
        try:
            opt = self.OptionCode(code)

            if opt in (self.OptionCode.CLIENT_ID, self.OptionCode.SERVER_ID):
                return self._decode_duid(value)

            elif opt == self.OptionCode.IA_NA:
                # [ IAID (4B) ][ T1 (4B) ][ T2 (4B) ][ Options (variable) ]
                iaid = int.from_bytes(value[0:4], "big")
                t1 = int.from_bytes(value[4:8], "big")
                t2 = int.from_bytes(value[8:12], "big")
                sub = self._parse_options(value[12:])
                return f"iaid={hex(iaid)} t1={t1}s t2={t2}s options={sub}"

            elif opt == self.OptionCode.IA_TA:
                # [ IAID (4B) ][ Options (variable) ]
                iaid = int.from_bytes(value[0:4], "big")
                sub = self._parse_options(value[4:])
                return f"iaid={hex(iaid)} options={sub}"

            elif opt == self.OptionCode.IA_ADDR:
                # [ Address (16B) ][ Preferred Lifetime (4B) ][ Valid Lifetime (4B) ]
                addr = socket.inet_ntop(socket.AF_INET6, value[0:16])
                preferred = int.from_bytes(value[16:20], "big")
                valid = int.from_bytes(value[20:24], "big")
                return f"{addr} preferred={preferred}s valid={valid}s"

            elif opt == self.OptionCode.IA_PD:
                # [ IAID (4B) ][ T1 (4B) ][ T2 (4B) ][ Options (variable) ]
                iaid = int.from_bytes(value[0:4], "big")
                t1 = int.from_bytes(value[4:8], "big")
                t2 = int.from_bytes(value[8:12], "big")
                sub = self._parse_options(value[12:])
                return f"iaid={hex(iaid)} t1={t1}s t2={t2}s options={sub}"

            elif opt == self.OptionCode.IA_PREFIX:
                # [ Preferred Lifetime (4B) ][ Valid Lifetime (4B) ]
                # [ Prefix Length (1B) ][ Prefix (16B) ]
                preferred = int.from_bytes(value[0:4], "big")
                valid = int.from_bytes(value[4:8], "big")
                prefix_len = value[8]
                prefix = socket.inet_ntop(socket.AF_INET6, value[9:25])
                return f"{prefix}/{prefix_len} preferred={preferred}s valid={valid}s"

            elif opt == self.OptionCode.ORO:
                # List of requested option codes (2B each)
                codes = []
                for j in range(0, len(value), 2):
                    c = int.from_bytes(value[j : j + 2], "big")
                    try:
                        codes.append(self.OptionCode(c).name)
                    except ValueError:
                        codes.append(str(c))
                return ", ".join(codes)

            elif opt == self.OptionCode.PREFERENCE:
                return str(value[0])

            elif opt == self.OptionCode.ELAPSED_TIME:
                # In hundredths of a second
                return f"{int.from_bytes(value, 'big') / 100:.2f}s"

            elif opt == self.OptionCode.STATUS_CODE:
                code_val = int.from_bytes(value[0:2], "big")
                msg = value[2:].decode("utf-8", errors="replace")
                try:
                    status = self.StatusCode(code_val).name.replace("_", " ").title()
                except ValueError:
                    status = str(code_val)
                return f"{status}: {msg}" if msg else status

            elif opt == self.OptionCode.DNS_SERVERS:
                addrs = [
                    socket.inet_ntop(socket.AF_INET6, value[j : j + 16])
                    for j in range(0, len(value), 16)
                ]
                return ", ".join(addrs)

            elif opt == self.OptionCode.DOMAIN_LIST:
                # Encoded as DNS wire format names
                names = []
                j = 0
                while j < len(value):
                    name, j = self._parse_dns_name(value, j)
                    if name:
                        names.append(name)
                return ", ".join(names)

            elif opt == self.OptionCode.RELAY_MSG:
                # Encapsulated DHCPv6 message
                inner = DHCPv6(value)
                return f"<encapsulated: {inner.msg_type_name()}>"

            elif opt in (self.OptionCode.RAPID_COMMIT, self.OptionCode.RECONF_ACCEPT):
                return "present"  # zero-length options — presence is the signal

            elif opt == self.OptionCode.UNICAST:
                return socket.inet_ntop(socket.AF_INET6, value)

            elif opt == self.OptionCode.FQDN:
                # [ Flags (1B) ][ Domain Name (DNS wire format) ]
                flags = value[0]
                name, _ = self._parse_dns_name(value, 1)
                return f"flags={bin(flags)} name={name}"

            elif opt in (self.OptionCode.SOL_MAX_RT, self.OptionCode.INF_MAX_RT):
                return f"{int.from_bytes(value, 'big')}s"

            elif opt == self.OptionCode.VENDOR_CLASS:
                en = int.from_bytes(value[0:4], "big")
                return f"enterprise={en} data={value[4:].hex()}"

            elif opt == self.OptionCode.BOOTFILE_URL:
                return value.decode("utf-8", errors="replace")

        except ValueError, IndexError:
            pass

        return value.hex()  # fallback for unknown/malformed options

    def _parse_dns_name(self, data: bytes, offset: int) -> tuple[str, int]:
        """Parse a DNS wire-format name (used in DOMAIN_LIST and FQDN options)."""
        labels = []
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            labels.append(
                data[offset : offset + length].decode("ascii", errors="replace")
            )
            offset += length
        return ".".join(labels), offset

    def msg_type_name(self) -> str:
        try:
            return self.MessageType(self.msg_type).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.msg_type})"

    def __str__(self) -> str:
        lines = [
            "--- DHCPv6 ".ljust(50, "-"),
            f"msg_type      = {self.msg_type} ({self.msg_type_name()}),",
        ]

        if self.xid is not None:
            lines.append(f"xid           = {hex(self.xid)},")

        if self.hop_count is not None:
            assert self.link_address is not None
            assert self.peer_address is not None
            lines += [
                f"hop_count     = {self.hop_count},",
                f"link_address  = {socket.inet_ntop(socket.AF_INET6, self.link_address)},",
                f"peer_address  = {socket.inet_ntop(socket.AF_INET6, self.peer_address)},",
            ]

        if self.options:
            lines.append("\n  Options:")
            for code, value in self.options.items():
                try:
                    name = self.OptionCode(code).name
                except ValueError:
                    name = f"Option({code})"
                lines.append(f"    {name:<24} {value}")

        return "\n".join(lines) + "\n"


class HTTP:
    """HTTP/1.x parser — RFC 7230/7231."""

    class Method(str, Enum):
        GET = "GET"
        POST = "POST"
        PUT = "PUT"
        DELETE = "DELETE"
        HEAD = "HEAD"
        OPTIONS = "OPTIONS"
        PATCH = "PATCH"
        TRACE = "TRACE"
        CONNECT = "CONNECT"

    class Version(str, Enum):
        HTTP_1_0 = "HTTP/1.0"
        HTTP_1_1 = "HTTP/1.1"

    # Common status code ranges
    STATUS_RANGES = {
        1: "Informational",
        2: "Success",
        3: "Redirection",
        4: "Client Error",
        5: "Server Error",
    }

    def __init__(self, data: bytes) -> None:
        # HTTP/1.x is text-based — decode as UTF-8 with fallback
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        # Headers and body are separated by a blank line (CRLF CRLF)
        if "\r\n\r\n" in text:
            header_section, self.body = text.split("\r\n\r\n", 1)
        else:
            header_section = text
            self.body = ""

        lines = header_section.split("\r\n")
        start_line = lines[0]

        # Determine if request or response from the start line
        if start_line.startswith("HTTP/"):
            self.is_response = True
            self.is_request = False
            self._parse_response(start_line)
        else:
            self.is_request = True
            self.is_response = False
            self._parse_request(start_line)

        # Parse headers — [ Field Name ]: [ Field Value ]
        self.headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                name, _, value = line.partition(": ")
                self.headers[name.lower()] = value.strip()

        # Decode body if transfer-encoding is chunked
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            self.body = self._decode_chunked(self.body)

    def _parse_request(self, start_line: str) -> None:
        """Parse HTTP request line — [ Method ][ SP ][ Request-URI ][ SP ][ Version ]"""
        parts = start_line.split(" ", 2)
        self.method = parts[0] if len(parts) > 0 else "?"
        self.uri = parts[1] if len(parts) > 1 else "?"
        self.version = parts[2] if len(parts) > 2 else "?"
        self.status_code = None
        self.reason_phrase = None

    def _parse_response(self, start_line: str) -> None:
        """Parse HTTP response line — [ Version ][ SP ][ Status Code ][ SP ][ Reason ]"""
        parts = start_line.split(" ", 2)
        self.version = parts[0] if len(parts) > 0 else "?"
        self.status_code = (
            int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        )
        self.reason_phrase = parts[2] if len(parts) > 2 else "?"
        self.method = None
        self.uri = None

    def _decode_chunked(self, body: str) -> str:
        """Decode chunked transfer encoding — RFC 7230 section 4.1."""
        decoded = []
        lines = body.split("\r\n")
        i = 0
        try:
            while i < len(lines):
                # Chunk size is a hex number, optionally followed by chunk extensions
                size = int(lines[i].split(";")[0].strip(), 16)
                i += 1
                if size == 0:
                    break
                decoded.append(lines[i][:size])
                i += 1
                i += 1  # skip trailing CRLF after chunk data
        except ValueError, IndexError:
            return body  # return raw if decoding fails
        return "".join(decoded)

    def status_range(self) -> str:
        if self.status_code is None:
            return ""
        return self.STATUS_RANGES.get(self.status_code // 100, "Unknown")

    def content_type(self) -> str:
        return self.headers.get("content-type", "unknown")

    def content_length(self) -> int | None:
        val = self.headers.get("content-length")
        return int(val) if val and val.isdigit() else None

    def __str__(self) -> str:
        lines = ["--- HTTP/1.x ".ljust(50, "-")]

        if self.is_request:
            lines += [
                "type     = Request,",
                f"method  = {self.method},",
                f"uri     = {self.uri},",
                f"version = {self.version},",
            ]
        else:
            lines += [
                "type     = Response,",
                f"version = {self.version},",
                f"status  = {self.status_code} {self.reason_phrase}"
                f" ({self.status_range()}),",
            ]

        if self.headers:
            lines.append("\n  Headers:")
            for name, value in self.headers.items():
                lines.append(f"    {name:<30} {value}")

        if self.body:
            # Truncate large bodies to avoid flooding the terminal
            preview = self.body[:256].replace("\r\n", " ").replace("\n", " ")
            if len(self.body) > 256:
                preview += f" ... ({len(self.body)} bytes total)"
            lines.append(f"\n  Body:\n    {preview}")

        return "\n".join(lines) + "\n"


@app.command()
def main(file: Annotated[str, typer.Argument(help="Raw packet binary file")]):
    # Read raw packet file
    try:
        with open(file, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        typer.echo(f"Error: file '{file}' not found.", err=True)
        raise typer.Exit(1)
    except OSError as e:
        typer.echo(f"Error reading file: {e}", err=True)
        raise typer.Exit(1)

    if len(raw) < 14:
        typer.echo("Error: file is too small to be a valid Ethernet frame.", err=True)
        raise typer.Exit(1)

    # Parse Ethernet frame
    frame = EthernetFrame(raw)
    typer.echo(frame)

    # Parse network layer
    pkg: IPv4 | IPv6 | None = None

    if frame.type == EtherType.IPv4:
        if len(frame.data) < 20:
            typer.echo("Error: IPv4 payload too short.", err=True)
            raise typer.Exit(1)
        pkg = IPv4(frame.data)
        typer.echo(pkg)

    elif frame.type == EtherType.IPv6:
        if len(frame.data) < 40:
            typer.echo("Error: IPv6 payload too short.", err=True)
            raise typer.Exit(1)
        pkg = IPv6(frame.data)
        typer.echo(pkg)

    elif frame.type == EtherType.ARP:
        if len(frame.data) < 8:
            typer.echo("Error: ARP packet too short.", err=True)
            raise typer.Exit(1)
        arp = ARP(frame.data)
        typer.echo(arp)
        raise typer.Exit(0)

    else:
        typer.echo(f"Unsupported EtherType: {hex(frame.type)}", err=True)
        raise typer.Exit(1)

    # Determine protocol from network layer
    protocol = pkg.protocol if isinstance(pkg, IPv4) else pkg.next_header

    # Parse transport layer
    if protocol == Protocol.UDP:
        if len(pkg.data) < 8:
            typer.echo("Error: UDP datagram too short.", err=True)
            raise typer.Exit(1)
        udp = UDP(pkg.data)
        typer.echo(udp)

        # DNS runs on port 53 (query or response)
        if udp.src_port == Port.DNS or udp.dst_port == Port.DNS:
            if len(udp.data) < 12:
                typer.echo("Error: DNS payload too short.", err=True)
                raise typer.Exit(1)
            dns = DNS(udp.data)
            typer.echo(dns)

        elif udp.src_port in (Port.DHCP_SERVER, Port.DHCP_CLIENT) or udp.dst_port in (
            Port.DHCP_SERVER,
            Port.DHCP_CLIENT,
        ):
            if len(udp.data) < 240:
                typer.echo("Error: DHCPv4 payload too short.", err=True)
                raise typer.Exit(1)
            dhcp = DHCPv4(udp.data)
            typer.echo(dhcp)

        elif udp.src_port in (
            Port.DHCP_V6_CLIENT,
            Port.DHCP_V6_SERVER,
        ) or udp.dst_port in (Port.DHCP_V6_CLIENT, Port.DHCP_V6_SERVER):
            if len(udp.data) < 4:
                typer.echo("Error: DHCPv6 payload too short.", err=True)
                raise typer.Exit(1)
            dhcp = DHCPv6(udp.data)
            typer.echo(dhcp)

    elif protocol == Protocol.TCP:
        if len(pkg.data) < 20:
            typer.echo("Error: TCP segment too short.", err=True)
            raise typer.Exit(1)
        tcp = TCP(pkg.data)
        typer.echo(tcp)

        if tcp.src_port in (Port.HTTP, Port.HTTPS) or tcp.dst_port in (
            Port.HTTP,
            Port.HTTPS,
        ):
            if tcp.data:
                http = HTTP(tcp.data)
                typer.echo(http)

    elif protocol == Protocol.ICMPv4:
        if len(pkg.data) < 8:
            typer.echo("Error: ICMP segment too short.", err=True)
            raise typer.Exit(1)
        icmp = ICMPv4(pkg.data)
        typer.echo(icmp)

    elif protocol == Protocol.ICMPv6:
        if len(pkg.data) < 8:
            typer.echo("Error: ICMPv6 segment too short.", err=True)
            raise typer.Exit(1)
        icmp = ICMPv6(pkg.data)
        typer.echo(icmp)

    else:
        typer.echo(f"Unsupported transport protocol: {protocol}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
