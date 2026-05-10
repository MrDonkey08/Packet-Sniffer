#!/usr/bin/env python3

from typing import Annotated
import typer

from protocols import (
    EtherType,
    Protocol,
    Port,
    EthernetFrame,
    ARP,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
    DNS,
    DHCPv4,
    DHCPv6,
    HTTP,
    ONC_RPC,
    NFSv4,
)

app = typer.Typer()


@app.command()
def main(file: Annotated[str, typer.Argument(help="Raw packet binary file")]):
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

        elif tcp.src_port == Port.NFS or tcp.dst_port == Port.NFS:
            if tcp.data:
                rpc_data = tcp.data[4:] if len(tcp.data) > 4 else tcp.data
                rpc = ONC_RPC(rpc_data)
                typer.echo(rpc)
                if rpc.program == 100003:
                    nfs = NFSv4(rpc)
                    typer.echo(nfs)

    elif protocol == Protocol.ICMPv4:
        if len(pkg.data) < 8:
            typer.echo("Error: ICMPv4 segment too short.", err=True)
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
