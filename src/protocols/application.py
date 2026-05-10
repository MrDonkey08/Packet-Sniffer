import socket
import struct
from enum import IntEnum, Enum


class DNS:
    """DNS parser — RFC 1035."""

    class QType(IntEnum):
        A = 1
        NS = 2
        CNAME = 5
        SOA = 6
        PTR = 12
        TXT = 16
        MX = 15
        AAAA = 28
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
        """Parse a DNS name following compression pointers — RFC 1035 section 4.1.4."""
        labels = []
        visited = set()
        end_offset = None

        while True:
            if offset in visited:
                raise ValueError(f"DNS name compression loop at offset {offset}")
            visited.add(offset)

            length = data[offset]

            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                if end_offset is None:
                    end_offset = offset + 2
                pointer = int.from_bytes(data[offset : offset + 2], "big") & 0x3FFF
                offset = pointer
            else:
                offset += 1
                labels.append(
                    data[offset : offset + length].decode("ascii", errors="replace")
                )
                offset += length

        return ".".join(labels), (end_offset if end_offset is not None else offset)

    def _parse_question(self, data: bytes, offset: int) -> tuple[dict, int]:
        name, offset = self._parse_name(data, offset)
        qtype = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        qclass = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        return {"name": name, "qtype": qtype, "qclass": qclass}, offset

    def _parse_rr(self, data: bytes, offset: int) -> tuple[dict, int]:
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
        rdata_decoded = self._decode_rdata(data, rtype, rdata, offset - rdlength)
        return {
            "name": name,
            "rtype": rtype,
            "rclass": rclass,
            "ttl": ttl,
            "rdata": rdata_decoded,
        }, offset

    def _decode_rdata(self, data: bytes, rtype: int, rdata: bytes, offset: int) -> str:
        # Falls back to hex on any parsing error — malformed rdata is expected in
        # the wild, so the except branch returns rather than passing silently.
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
                mname, off = self._parse_name(data, offset)
                rname, off = self._parse_name(data, off)
                serial = int.from_bytes(data[off : off + 4], "big")
                return f"mname={mname} rname={rname} serial={serial}"
            elif rtype == self.QType.SRV:
                priority = int.from_bytes(rdata[0:2], "big")
                weight = int.from_bytes(rdata[2:4], "big")
                port = int.from_bytes(rdata[4:6], "big")
                target, _ = self._parse_name(data, offset + 6)
                return f"{priority} {weight} {port} {target}"
        except ValueError, IndexError, struct.error, UnicodeDecodeError, OSError:
            return rdata.hex()
        return rdata.hex()

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
                f"    {rr['name']:<30} {rr['ttl']:<8} "
                f"{self.qclass_name(rr['rclass']):<6} "
                f"{self.qtype_name(rr['rtype']):<8} {rr['rdata']}"
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
            f"{'CD ' if self.flag_cd else ''}".strip()
            + ",",
            f"questions   = {self.qdcount},",
            f"answers     = {self.ancount},",
            f"authorities = {self.nscount},",
            f"additionals = {self.arcount},",
        ]

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
        self.hlen = data[2]
        self.hops = data[3]

        self.xid = int.from_bytes(data[4:8], "big")
        self.secs = int.from_bytes(data[8:10], "big")
        flags = int.from_bytes(data[10:12], "big")
        self.flag_broadcast = bool((flags >> 15) & 0x1)

        self.ciaddr = data[12:16]
        self.yiaddr = data[16:20]
        self.siaddr = data[20:24]
        self.giaddr = data[24:28]
        self.chaddr = data[28 : 28 + self.hlen]
        self.sname = data[44:108].rstrip(b"\x00").decode("ascii", errors="replace")
        self.file = data[108:236].rstrip(b"\x00").decode("ascii", errors="replace")

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
            if code == 0:
                continue  # Pad — no length byte
            if code == 255:
                break  # End
            length = data[i]
            i += 1
            value = data[i : i + length]
            i += length
            options[code] = self._decode_option(code, value)
        return options

    def _decode_option(self, code: int, value: bytes) -> object:
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
                return ", ".join(
                    socket.inet_ntoa(value[j : j + 4]) for j in range(0, len(value), 4)
                )
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
                return f"htype={value[0]} addr={value[1:].hex(':')}"
            elif opt == self.Option.PARAM_REQUEST_LIST:
                names = []
                for c in value:
                    try:
                        names.append(self.Option(c).name)
                    except ValueError:
                        names.append(str(c))
                return ", ".join(names)
            elif opt == self.Option.CLASSLESS_ROUTE:
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
        return value.hex()

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
            f"ciaddr         = {socket.inet_ntoa(self.ciaddr)},",
            f"yiaddr         = {socket.inet_ntoa(self.yiaddr)},",
            f"siaddr         = {socket.inet_ntoa(self.siaddr)},",
            f"giaddr         = {socket.inet_ntoa(self.giaddr)},",
            f"chaddr         = {self.chaddr.hex(':')},",
        ]
        if self.sname:
            lines.append(f"sname          = {self.sname},")
        if self.file:
            lines.append(f"file           = {self.file},")
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
        IA_NA = 3
        IA_TA = 4
        IA_ADDR = 5
        ORO = 6
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
        IA_PD = 25  # RFC 3633
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
        LLT = 1
        EN = 2
        LL = 3
        UUID = 4

    def __init__(self, data: bytes) -> None:
        self.msg_type = data[0]

        if self.msg_type in (self.MessageType.RELAY_FORW, self.MessageType.RELAY_REPL):
            # [ Msg Type (1B) ][ Hop Count (1B) ][ Link Address (16B) ][ Peer Address (16B) ]
            self.hop_count: int | None = data[1]
            self.link_address: bytes | None = data[2:18]
            self.peer_address: bytes | None = data[18:34]
            self.options = self._parse_options(data[34:])
            self.xid = None
        else:
            # [ Msg Type (1B) ][ Transaction ID (3B) ][ Options (variable) ]
            self.hop_count = None
            self.link_address = None
            self.peer_address = None
            self.xid = int.from_bytes(data[1:4], "big")
            self.options = self._parse_options(data[4:])

    def _parse_options(self, data: bytes) -> dict[int, object]:
        """All options: [ Code (2B) ][ Length (2B) ][ Value (Length B) ]"""
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
        if len(data) < 2:
            return data.hex()
        duid_type = int.from_bytes(data[0:2], "big")
        try:
            dtype = self.DUIDType(duid_type)
            if dtype == self.DUIDType.LLT:
                hw_type = int.from_bytes(data[2:4], "big")
                time = int.from_bytes(data[4:8], "big")
                return f"LLT hw_type={hw_type} time={time} addr={data[8:].hex(':')}"
            elif dtype == self.DUIDType.EN:
                en = int.from_bytes(data[2:6], "big")
                return f"EN enterprise={en} id={data[6:].hex()}"
            elif dtype == self.DUIDType.LL:
                hw_type = int.from_bytes(data[2:4], "big")
                return f"LL hw_type={hw_type} addr={data[4:].hex(':')}"
            elif dtype == self.DUIDType.UUID:
                return f"UUID {data[2:].hex()}"
        except ValueError:
            pass
        return data.hex()

    def _decode_option(self, code: int, value: bytes, full_data: bytes) -> object:
        try:
            opt = self.OptionCode(code)
            if opt in (self.OptionCode.CLIENT_ID, self.OptionCode.SERVER_ID):
                return self._decode_duid(value)
            elif opt == self.OptionCode.IA_NA:
                iaid = int.from_bytes(value[0:4], "big")
                t1 = int.from_bytes(value[4:8], "big")
                t2 = int.from_bytes(value[8:12], "big")
                sub = self._parse_options(value[12:])
                return f"iaid={hex(iaid)} t1={t1}s t2={t2}s options={sub}"
            elif opt == self.OptionCode.IA_TA:
                iaid = int.from_bytes(value[0:4], "big")
                sub = self._parse_options(value[4:])
                return f"iaid={hex(iaid)} options={sub}"
            elif opt == self.OptionCode.IA_ADDR:
                addr = socket.inet_ntop(socket.AF_INET6, value[0:16])
                preferred = int.from_bytes(value[16:20], "big")
                valid = int.from_bytes(value[20:24], "big")
                return f"{addr} preferred={preferred}s valid={valid}s"
            elif opt == self.OptionCode.IA_PD:
                iaid = int.from_bytes(value[0:4], "big")
                t1 = int.from_bytes(value[4:8], "big")
                t2 = int.from_bytes(value[8:12], "big")
                sub = self._parse_options(value[12:])
                return f"iaid={hex(iaid)} t1={t1}s t2={t2}s options={sub}"
            elif opt == self.OptionCode.IA_PREFIX:
                preferred = int.from_bytes(value[0:4], "big")
                valid = int.from_bytes(value[4:8], "big")
                prefix_len = value[8]
                prefix = socket.inet_ntop(socket.AF_INET6, value[9:25])
                return f"{prefix}/{prefix_len} preferred={preferred}s valid={valid}s"
            elif opt == self.OptionCode.ORO:
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
                return ", ".join(
                    socket.inet_ntop(socket.AF_INET6, value[j : j + 16])
                    for j in range(0, len(value), 16)
                )
            elif opt == self.OptionCode.DOMAIN_LIST:
                names = []
                j = 0
                while j < len(value):
                    name, j = self._parse_dns_name(value, j)
                    if name:
                        names.append(name)
                return ", ".join(names)
            elif opt == self.OptionCode.RELAY_MSG:
                inner = DHCPv6(value)
                return f"<encapsulated: {inner.msg_type_name()}>"
            elif opt in (self.OptionCode.RAPID_COMMIT, self.OptionCode.RECONF_ACCEPT):
                return "present"
            elif opt == self.OptionCode.UNICAST:
                return socket.inet_ntop(socket.AF_INET6, value)
            elif opt == self.OptionCode.FQDN:
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
        return value.hex()

    def _parse_dns_name(self, data: bytes, offset: int) -> tuple[str, int]:
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
        if (
            self.hop_count is not None
            and self.link_address is not None
            and self.peer_address is not None
        ):
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

    STATUS_RANGES = {
        1: "Informational",
        2: "Success",
        3: "Redirection",
        4: "Client Error",
        5: "Server Error",
    }

    def __init__(self, data: bytes) -> None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")

        if "\r\n\r\n" in text:
            header_section, self.body = text.split("\r\n\r\n", 1)
        else:
            header_section = text
            self.body = ""

        lines = header_section.split("\r\n")
        start_line = lines[0]

        # Declare all fields up front so mypy sees a consistent type across
        # both the request and response parse paths.
        self.is_request: bool = False
        self.is_response: bool = False
        self.method: str | None = None
        self.uri: str | None = None
        self.version: str = "?"
        self.status_code: int | None = None
        self.reason_phrase: str | None = None

        if start_line.startswith("HTTP/"):
            self.is_response = True
            self._parse_response(start_line)
        else:
            self.is_request = True
            self._parse_request(start_line)

        self.headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                name, _, value = line.partition(": ")
                self.headers[name.lower()] = value.strip()

        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            self.body = self._decode_chunked(self.body)

    def _parse_request(self, start_line: str) -> None:
        """Parse HTTP request line — [ Method ][ SP ][ Request-URI ][ SP ][ Version ]"""
        parts = start_line.split(" ", 2)
        self.method = parts[0] if len(parts) > 0 else "?"
        self.uri = parts[1] if len(parts) > 1 else "?"
        self.version = parts[2] if len(parts) > 2 else "?"

    def _parse_response(self, start_line: str) -> None:
        """Parse HTTP response line — [ Version ][ SP ][ Status Code ][ SP ][ Reason ]"""
        parts = start_line.split(" ", 2)
        self.version = parts[0] if len(parts) > 0 else "?"
        self.status_code = (
            int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        )
        self.reason_phrase = parts[2] if len(parts) > 2 else "?"

    def _decode_chunked(self, body: str) -> str:
        """Decode chunked transfer encoding — RFC 7230 section 4.1."""
        decoded = []
        lines = body.split("\r\n")
        i = 0
        try:
            while i < len(lines):
                size = int(lines[i].split(";")[0].strip(), 16)
                i += 1
                if size == 0:
                    break
                decoded.append(lines[i][:size])
                i += 1
                i += 1  # skip trailing CRLF after chunk data
        except ValueError, IndexError:
            return body
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
                f"status  = {self.status_code} {self.reason_phrase} ({self.status_range()}),",
            ]
        if self.headers:
            lines.append("\n  Headers:")
            for name, value in self.headers.items():
                lines.append(f"    {name:<30} {value}")
        if self.body:
            preview = self.body[:256].replace("\r\n", " ").replace("\n", " ")
            if len(self.body) > 256:
                preview += f" ... ({len(self.body)} bytes total)"
            lines.append(f"\n  Body:\n    {preview}")
        return "\n".join(lines) + "\n"


class ONC_RPC:
    """ONC RPC parser — RFC 5531."""

    class MessageType(IntEnum):
        CALL = 0
        REPLY = 1

    class ReplyStatus(IntEnum):
        MSG_ACCEPTED = 0
        MSG_DENIED = 1

    class AcceptStatus(IntEnum):
        SUCCESS = 0
        PROG_UNAVAIL = 1
        PROG_MISMATCH = 2
        PROC_UNAVAIL = 3
        GARBAGE_ARGS = 4
        SYSTEM_ERR = 5

    class RejectStatus(IntEnum):
        RPC_MISMATCH = 0
        AUTH_ERROR = 1

    class AuthFlavor(IntEnum):
        AUTH_NONE = 0
        AUTH_SYS = 1
        AUTH_SHORT = 2
        AUTH_DH = 3
        RPCSEC_GSS = 6

    def __init__(self, data: bytes) -> None:
        # [ XID (4B) ][ Message Type (4B) ][ Body (variable) ]
        self.xid = int.from_bytes(data[0:4], "big")
        self.msg_type = int.from_bytes(data[4:8], "big")
        offset = 8

        # Declare all optional fields up front so mypy sees consistent types
        # regardless of which parse path (CALL vs REPLY) is taken.
        self.rpc_version: int | None = None
        self.program: int | None = None
        self.prog_version: int | None = None
        self.procedure: int | None = None
        self.cred: dict | None = None
        self.verf: dict | None = None
        self.reply_status: int | None = None
        self.accept_status: int | None = None
        self.reject_status: int | None = None

        if self.msg_type == self.MessageType.CALL:
            offset = self._parse_call(data, offset)
        elif self.msg_type == self.MessageType.REPLY:
            offset = self._parse_reply(data, offset)

        self.data = data[offset:]

    def _parse_auth(self, data: bytes, offset: int) -> tuple[dict, int]:
        """[ Flavor (4B) ][ Length (4B) ][ Body (Length B) ]"""
        flavor = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        length = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        body = data[offset : offset + length]
        offset += length
        decoded: dict = {"flavor": flavor, "length": length}

        if flavor == self.AuthFlavor.AUTH_SYS and length >= 12:
            stamp = int.from_bytes(body[0:4], "big")
            name_len = int.from_bytes(body[4:8], "big")
            name = body[8 : 8 + name_len].decode("ascii", errors="replace")
            off = 8 + name_len + (4 - name_len % 4) % 4
            uid = int.from_bytes(body[off : off + 4], "big")
            off += 4
            gid = int.from_bytes(body[off : off + 4], "big")
            off += 4
            gid_count = int.from_bytes(body[off : off + 4], "big")
            off += 4
            gids = [
                int.from_bytes(body[off + j * 4 : off + j * 4 + 4], "big")
                for j in range(gid_count)
            ]
            decoded.update(
                {"stamp": stamp, "machine": name, "uid": uid, "gid": gid, "gids": gids}
            )

        return decoded, offset

    def _parse_call(self, data: bytes, offset: int) -> int:
        """[ RPC Version (4B) ][ Program (4B) ][ Prog Version (4B) ][ Procedure (4B) ][ Cred ][ Verf ]"""
        self.rpc_version = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        self.program = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        self.prog_version = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        self.procedure = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        self.cred, offset = self._parse_auth(data, offset)
        self.verf, offset = self._parse_auth(data, offset)
        return offset

    def _parse_reply(self, data: bytes, offset: int) -> int:
        """[ Reply Status (4B) ][ Verifier or Reject Status ][ Accept Status ]"""
        self.reply_status = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4

        if self.reply_status == self.ReplyStatus.MSG_ACCEPTED:
            self.verf, offset = self._parse_auth(data, offset)
            self.accept_status = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
        elif self.reply_status == self.ReplyStatus.MSG_DENIED:
            self.reject_status = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4

        return offset

    def msg_type_name(self) -> str:
        try:
            return self.MessageType(self.msg_type).name.title()
        except ValueError:
            return f"Unknown ({self.msg_type})"

    def accept_status_name(self) -> str:
        if self.accept_status is None:
            return "N/A"
        try:
            return self.AcceptStatus(self.accept_status).name.replace("_", " ").title()
        except ValueError:
            return f"Unknown ({self.accept_status})"

    def program_name(self) -> str:
        if self.program is None:
            return "N/A"
        return {
            100003: "NFS",
            100005: "Mount",
            100021: "NLM (Lock Manager)",
            100024: "Status Monitor",
        }.get(self.program, f"Unknown ({self.program})")

    def __str__(self) -> str:
        lines = [
            "--- ONC RPC ".ljust(50, "-"),
            f"xid           = {hex(self.xid)},",
            f"msg_type      = {self.msg_type} ({self.msg_type_name()}),",
        ]
        if (
            self.msg_type == self.MessageType.CALL
            and self.program is not None
            and self.prog_version is not None
            and self.procedure is not None
            and self.cred is not None
        ):
            lines += [
                f"rpc_version   = {self.rpc_version},",
                f"program       = {self.program} ({self.program_name()}),",
                f"prog_version  = {self.prog_version},",
                f"procedure     = {self.procedure},",
                f"cred_flavor   = {self.cred['flavor']},",
            ]
            if "machine" in self.cred:
                lines += [
                    f"cred_machine  = {self.cred['machine']},",
                    f"cred_uid      = {self.cred['uid']},",
                    f"cred_gid      = {self.cred['gid']},",
                ]
        elif self.msg_type == self.MessageType.REPLY:
            lines.append(f"reply_status  = {self.reply_status},")
            if self.accept_status is not None:
                lines.append(
                    f"accept_status = {self.accept_status} ({self.accept_status_name()}),"
                )
            if self.reject_status is not None:
                lines.append(f"reject_status = {self.reject_status},")
        return "\n".join(lines) + "\n"


class NFSv4:
    """NFSv4 parser — RFC 7530."""

    class Procedure(IntEnum):
        NULL = 0
        COMPOUND = 1

    class OpCode(IntEnum):
        ACCESS = 3
        CLOSE = 4
        COMMIT = 5
        CREATE = 6
        DELEGPURGE = 7
        DELEGRETURN = 8
        GETATTR = 9
        GETFH = 10
        LINK = 11
        LOCK = 12
        LOCKT = 13
        LOCKU = 14
        LOOKUP = 15
        LOOKUPP = 16
        NVERIFY = 17
        OPEN = 18
        OPENATTR = 19
        OPEN_CONFIRM = 20
        OPEN_DOWNGRADE = 21
        PUTFH = 22
        PUTPUBFH = 23
        PUTROOTFH = 24
        READ = 25
        READDIR = 26
        READLINK = 27
        REMOVE = 28
        RENAME = 29
        RENEW = 30
        RESTOREFH = 31
        SAVEFH = 32
        SECINFO = 33
        SETATTR = 34
        SETCLIENTID = 35
        SETCLIENTID_CONFIRM = 36
        VERIFY = 37
        WRITE = 38
        RELEASE_LOCKOWNER = 39

    class NFSStatus(IntEnum):
        OK = 0
        PERM = 1
        NOENT = 2
        IO = 5
        NXIO = 6
        ACCES = 13
        EXIST = 17
        XDEV = 18
        NODEV = 19
        NOTDIR = 20
        ISDIR = 21
        INVAL = 22
        FBIG = 27
        NOSPC = 28
        ROFS = 30
        MLINK = 31
        NAMETOOLONG = 63
        NOTEMPTY = 66
        DQUOT = 69
        STALE = 70
        BADHANDLE = 10001
        NOT_SYNC = 10002
        BAD_COOKIE = 10003
        NOTSUPP = 10004
        TOOSMALL = 10005
        SERVERFAULT = 10006
        BADTYPE = 10007
        DELAY = 10008
        SAME = 10009
        DENIED = 10010
        EXPIRED = 10011
        LOCKED = 10012
        GRACE = 10013
        FHEXPIRED = 10014
        SHARE_DENIED = 10015
        WRONGSEC = 10016
        CLID_INUSE = 10017
        RESOURCE = 10018
        MOVED = 10019
        NOFILEHANDLE = 10020
        MINOR_VERS_MISMATCH = 10021
        STALE_CLIENTID = 10022
        STALE_STATEID = 10023
        OLD_STATEID = 10024
        BAD_STATEID = 10025
        BAD_SEQID = 10026
        NOT_SAME = 10027
        LOCK_RANGE = 10028
        SYMLINK = 10029
        RESTOREFH = 10030
        LEASE_MOVED = 10031
        ATTRNOTSUPP = 10032
        NO_GRACE = 10033
        RECLAIM_BAD = 10034
        RECLAIM_CONFLICT = 10035
        BADXDR = 10036
        LOCKS_HELD = 10037
        OPENMODE = 10038
        BADOWNER = 10039
        BADCHAR = 10040
        BADNAME = 10041
        BAD_RANGE = 10042
        LOCK_NOTSUPP = 10043
        OP_ILLEGAL = 10044
        DEADLOCK = 10045
        FILE_OPEN = 10046
        ADMIN_REVOKED = 10047
        CB_PATH_DOWN = 10048

    class WriteStable(IntEnum):
        UNSTABLE = 0
        DATA_SYNC = 1
        FILE_SYNC = 2

    def __init__(self, rpc: ONC_RPC) -> None:
        data = rpc.data

        # Declare all fields up front for consistent typing across both paths.
        self.status: int | None = None
        self.tag: str = ""
        self.minor_version: int | None = None
        self.operations: list[dict] = []

        if rpc.msg_type == ONC_RPC.MessageType.CALL:
            self._parse_call(data, rpc.procedure)
        else:
            self._parse_reply(data)

    def _read_str(self, data: bytes, offset: int) -> tuple[str, int]:
        """[ Length (4B) ][ Data (Length B) ][ Padding to 4B boundary ]"""
        length = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        value = data[offset : offset + length].decode("utf-8", errors="replace")
        offset += length
        offset += (4 - length % 4) % 4
        return value, offset

    def _read_opaque(self, data: bytes, offset: int) -> tuple[bytes, int]:
        """[ Length (4B) ][ Data (Length B) ][ Padding to 4B boundary ]"""
        length = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        value = data[offset : offset + length]
        offset += length
        offset += (4 - length % 4) % 4
        return value, offset

    def _parse_call(self, data: bytes, procedure: int | None) -> None:
        if procedure == self.Procedure.NULL:
            self.tag = "NULL"
            return

        offset = 0
        self.tag, offset = self._read_str(data, offset)
        self.minor_version = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        op_count = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4

        for _ in range(op_count):
            if offset + 4 > len(data):
                break
            op_code = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
            op, offset = self._parse_op_call(data, offset, op_code)
            self.operations.append(op)

    def _parse_reply(self, data: bytes) -> None:
        if len(data) < 4:
            return

        offset = 0
        self.status = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        self.tag, offset = self._read_str(data, offset)
        op_count = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4

        for _ in range(op_count):
            if offset + 8 > len(data):
                break
            op_code = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
            status = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
            op, offset = self._parse_op_reply(data, offset, op_code, status)
            self.operations.append(op)

    def _parse_op_call(
        self, data: bytes, offset: int, op_code: int
    ) -> tuple[dict, int]:
        op: dict = {"op_code": op_code, "op_name": self._op_name(op_code)}
        try:
            if op_code == self.OpCode.LOOKUP:
                name, offset = self._read_str(data, offset)
                op["name"] = name
            elif op_code == self.OpCode.OPEN:
                op["seq_id"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                op["share_access"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                op["share_deny"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            elif op_code == self.OpCode.READ:
                op["stateid"] = data[offset : offset + 16].hex()
                offset += 16
                op["offset"] = int.from_bytes(data[offset : offset + 8], "big")
                offset += 8
                op["count"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            elif op_code == self.OpCode.WRITE:
                op["stateid"] = data[offset : offset + 16].hex()
                offset += 16
                op["offset"] = int.from_bytes(data[offset : offset + 8], "big")
                offset += 8
                op["stable"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                data_bytes, offset = self._read_opaque(data, offset)
                op["data_len"] = len(data_bytes)
            elif op_code == self.OpCode.REMOVE:
                name, offset = self._read_str(data, offset)
                op["name"] = name
            elif op_code == self.OpCode.RENAME:
                old, offset = self._read_str(data, offset)
                new, offset = self._read_str(data, offset)
                op["old_name"] = old
                op["new_name"] = new
            elif op_code == self.OpCode.SETCLIENTID:
                op["verifier"] = data[offset : offset + 8].hex()
                offset += 8
                client_id, offset = self._read_opaque(data, offset)
                op["client_id"] = client_id.hex()
            elif op_code == self.OpCode.GETATTR:
                word_count = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                bitmap = [
                    int.from_bytes(data[offset + i * 4 : offset + i * 4 + 4], "big")
                    for i in range(word_count)
                ]
                offset += word_count * 4
                op["attr_bitmap"] = [hex(b) for b in bitmap]
        except IndexError, struct.error:
            pass
        return op, offset

    def _parse_op_reply(
        self, data: bytes, offset: int, op_code: int, status: int
    ) -> tuple[dict, int]:
        op: dict = {
            "op_code": op_code,
            "op_name": self._op_name(op_code),
            "status": status,
            "status_name": self._status_name(status),
        }
        if status != self.NFSStatus.OK:
            return op, offset
        try:
            if op_code == self.OpCode.READ:
                op["eof"] = bool(int.from_bytes(data[offset : offset + 4], "big"))
                offset += 4
                rd, offset = self._read_opaque(data, offset)
                op["data_len"] = len(rd)
            elif op_code == self.OpCode.WRITE:
                op["count"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                op["stable"] = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
                op["verifier"] = data[offset : offset + 8].hex()
                offset += 8
            elif op_code == self.OpCode.GETFH:
                fh, offset = self._read_opaque(data, offset)
                op["filehandle"] = fh.hex()
            elif op_code == self.OpCode.SETCLIENTID:
                op["client_id"] = int.from_bytes(data[offset : offset + 8], "big")
                offset += 8
                op["verifier"] = data[offset : offset + 8].hex()
                offset += 8
        except IndexError, struct.error:
            pass
        return op, offset

    def _op_name(self, op_code: int) -> str:
        try:
            return self.OpCode(op_code).name
        except ValueError:
            return f"Unknown ({op_code})"

    def _status_name(self, status: int) -> str:
        try:
            return self.NFSStatus(status).name
        except ValueError:
            return f"Unknown ({status})"

    def __str__(self) -> str:
        lines = ["--- NFSv4 ".ljust(50, "-")]
        if self.status is not None:
            lines.append(
                f"status        = {self.status} ({self._status_name(self.status)}),"
            )
        if self.tag:
            lines.append(f"tag           = {self.tag!r},")
        if self.minor_version is not None:
            lines.append(f"minor_version = {self.minor_version},")
        if self.operations:
            lines.append("\n  Operations:")
            for op in self.operations:
                line = f"    {op['op_name']:<24}"
                if "status" in op:
                    line += f" [{op['status_name']}]"
                for key, val in op.items():
                    if key not in ("op_code", "op_name", "status", "status_name"):
                        line += f"  {key}={val}"
                lines.append(line)
        return "\n".join(lines) + "\n"
