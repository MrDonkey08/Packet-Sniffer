#!/usr/bin/env python3

from typing import Annotated
import typer
import socket

app = typer.Typer()

# EtherType constants
TYPE_IPv4 = 0x0800
TYPE_IPv6 = 0x86DD
TYPE_ARP = 0x0806

# IPv4 protocol constants
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


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
            f"EthernetFrame(src={self.format_mac(self.src_mac)}, "
            f"dst={self.format_mac(self.dst_mac)}, "
            f"type={hex(self.type)}, "
            f"vlan={self.vlan_tag.hex() if self.vlan_tag else None})"
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
            f"IPv4(src={self.format_ip(self.src_ip)}, "
            f"dst={self.format_ip(self.dst_ip)}, "
            f"proto={self.protocol}, ttl={self.ttl}, "
            f"flags={bin(self.flags)}, frag_offset={self.fragment_offset})"
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
            f"IPv6(src={self.format_ip(self.src_ip)}, "
            f"dst={self.format_ip(self.dst_ip)}, "
            f"next_header={self.next_header}, hop_limit={self.hop_limit})"
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
            f"UDP(src_port={self.src_port}, dst_port={self.dst_port}, "
            f"length={self.length}, checksum={hex(self.checksum)})"
        )


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

    if frame.type == TYPE_IPv4:
        if len(frame.data) < 20:
            typer.echo("Error: IPv4 payload too short.", err=True)
            raise typer.Exit(1)
        pkg = IPv4(frame.data)
        typer.echo(pkg)

    elif frame.type == TYPE_IPv6:
        if len(frame.data) < 40:
            typer.echo("Error: IPv6 payload too short.", err=True)
            raise typer.Exit(1)
        pkg = IPv6(frame.data)
        typer.echo(pkg)

    elif frame.type == TYPE_ARP:
        typer.echo("ARP packet detected — no further parsing implemented.")
        raise typer.Exit(0)

    else:
        typer.echo(f"Unsupported EtherType: {hex(frame.type)}", err=True)
        raise typer.Exit(1)

    # Determine protocol from network layer
    protocol = pkg.protocol if isinstance(pkg, IPv4) else pkg.next_header

    # Parse transport layer
    if protocol == PROTO_UDP:
        if len(pkg.data) < 8:
            typer.echo("Error: UDP datagram too short.", err=True)
            raise typer.Exit(1)
        udp = UDP(pkg.data)
        typer.echo(udp)

    elif protocol == PROTO_TCP:
        typer.echo("TCP packet detected — no further parsing implemented.")

    elif protocol == PROTO_ICMP:
        typer.echo("ICMP packet detected — no further parsing implemented.")

    else:
        typer.echo(f"Unsupported transport protocol: {protocol}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
