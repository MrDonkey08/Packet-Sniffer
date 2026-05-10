import socket
from enum import IntEnum

from .constants import EtherType


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
            self.vlan_tag: bytes | None = frame[14:16]  # PCP (3b), DEI (1b), VID (12b)
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

    def format_proto(self, addr: bytes) -> str:
        if self.ptype == EtherType.IPv4 and len(addr) == 4:
            return socket.inet_ntoa(addr)
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
