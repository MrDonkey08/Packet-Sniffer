import socket
from enum import IntEnum


class UDP:
    def __init__(self, datagram: bytes) -> None:
        # UDP header structure (8 bytes fixed):
        # [ Src Port (2B) ][ Dst Port (2B) ][ Length (2B) ][ Checksum (2B) ][ Payload ]
        self.src_port = int.from_bytes(datagram[0:2], "big")
        self.dst_port = int.from_bytes(datagram[2:4], "big")
        self.length = int.from_bytes(datagram[4:6], "big")  # header + payload
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
    class Type(IntEnum):
        ECHO_REPLY = 0
        DEST_UNREACHABLE = 3
        REDIRECT = 5
        ECHO_REQUEST = 8
        TIME_EXCEEDED = 11
        PARAMETER_PROBLEM = 12
        TIMESTAMP_REQUEST = 13
        TIMESTAMP_REPLY = 14

    class CodeDestUnreachable(IntEnum):
        NET_UNREACHABLE = 0
        HOST_UNREACHABLE = 1
        PROTO_UNREACHABLE = 2
        PORT_UNREACHABLE = 3
        FRAGMENTATION_NEEDED = 4
        SOURCE_ROUTE_FAILED = 5

    class CodeTimeExceeded(IntEnum):
        TTL_EXCEEDED = 0
        FRAGMENT_REASSEMBLY = 1

    class CodeRedirect(IntEnum):
        REDIRECT_NET = 0
        REDIRECT_HOST = 1
        REDIRECT_TOS_NET = 2
        REDIRECT_TOS_HOST = 3

    def __init__(self, segment: bytes) -> None:
        # ICMPv4 base header structure (8 bytes fixed):
        # [ Type (1B) ][ Code (1B) ][ Checksum (2B) ][ Rest of Header (4B) ]
        self.type = segment[0]
        self.code = segment[1]
        self.checksum = int.from_bytes(segment[2:4], "big")

        # Bytes 4-7 are type-dependent
        rest = segment[4:8]

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

        elif self.type in (self.Type.TIMESTAMP_REQUEST, self.Type.TIMESTAMP_REPLY):
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

        self.original_datagram = None

        if self.type == self.Type.DEST_UNREACHABLE:
            pass  # [ Unused (4B) ]

        elif self.type == self.Type.PACKET_TOO_BIG:
            self.mtu = int.from_bytes(rest[0:4], "big")

        elif self.type == self.Type.TIME_EXCEEDED:
            pass  # [ Unused (4B) ]

        elif self.type == self.Type.PARAMETER_PROBLEM:
            self.pointer = int.from_bytes(rest[0:4], "big")

        elif self.type in (self.Type.ECHO_REQUEST, self.Type.ECHO_REPLY):
            self.identifier = int.from_bytes(rest[0:2], "big")
            self.sequence_num = int.from_bytes(rest[2:4], "big")

        elif self.type == self.Type.ROUTER_SOLICITATION:
            self.ndp_options = segment[8:]

        elif self.type == self.Type.ROUTER_ADVERTISEMENT:
            self.cur_hop_limit = rest[0]
            ra_flags = rest[1]
            self.ra_flag_managed = bool(ra_flags & 0x80)
            self.ra_flag_other = bool(ra_flags & 0x40)
            self.router_lifetime = int.from_bytes(rest[2:4], "big")
            self.reachable_time = int.from_bytes(segment[8:12], "big")
            self.retrans_timer = int.from_bytes(segment[12:16], "big")
            self.ndp_options = segment[16:]

        elif self.type == self.Type.NEIGHBOR_SOLICITATION:
            self.target_addr = segment[8:24]
            self.ndp_options = segment[24:]

        elif self.type == self.Type.NEIGHBOR_ADVERTISEMENT:
            na_flags = int.from_bytes(rest[0:4], "big")
            self.na_flag_router = bool(na_flags & 0x80000000)
            self.na_flag_solicited = bool(na_flags & 0x40000000)
            self.na_flag_override = bool(na_flags & 0x20000000)
            self.target_addr = segment[8:24]
            self.ndp_options = segment[24:]

        elif self.type == self.Type.REDIRECT:
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
                f"cur_hop_limit   = {self.cur_hop_limit},",
                f"flag_managed    = {self.ra_flag_managed},",
                f"flag_other      = {self.ra_flag_other},",
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
                    f"flag_router    = {self.na_flag_router},",
                    f"flag_solicited = {self.na_flag_solicited},",
                    f"flag_override  = {self.na_flag_override},",
                ]
        elif self.type == self.Type.REDIRECT:
            lines += [
                f"target_addr   = {self.format_ip(self.target_addr)},",
                f"dest_addr     = {self.format_ip(self.dest_addr)},",
            ]

        if self.original_datagram:
            lines.append(f"original_dgram= {self.original_datagram[:8].hex()} ...,")

        return "\n".join(lines) + "\n"
