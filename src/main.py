#!/usr/bin/env python3

from enum import IntEnum
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

    elif protocol == Protocol.TCP:
        if len(pkg.data) < 20:
            typer.echo("Error: TCP segment too short.", err=True)
            raise typer.Exit(1)
        tcp = TCP(pkg.data)
        typer.echo(tcp)

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
