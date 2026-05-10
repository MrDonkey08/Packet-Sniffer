#!/usr/bin/env python3

import signal
from typing import Annotated, Optional

import typer
from scapy.all import AsyncSniffer

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


def parse_and_print(raw: bytes) -> None:
    """Parse a raw packet and print each layer. Shared by file and live modes."""
    if len(raw) < 14:
        typer.echo("Warning: packet too small to be a valid Ethernet frame — skipping.")
        return

    # Parse Ethernet frame
    frame = EthernetFrame(raw)
    typer.echo(frame)

    pkg: IPv4 | IPv6 | None = None

    if frame.type == EtherType.IPv4:
        if len(frame.data) < 20:
            typer.echo("Warning: IPv4 payload too short — skipping.")
            return
        pkg = IPv4(frame.data)
        typer.echo(pkg)

    elif frame.type == EtherType.IPv6:
        if len(frame.data) < 40:
            typer.echo("Warning: IPv6 payload too short — skipping.")
            return
        pkg = IPv6(frame.data)
        typer.echo(pkg)

    elif frame.type == EtherType.ARP:
        if len(frame.data) < 8:
            typer.echo("Warning: ARP packet too short — skipping.")
            return
        arp = ARP(frame.data)
        typer.echo(arp)
        return

    else:
        typer.echo(f"Unsupported EtherType: {hex(frame.type)}")
        return

    # Determine protocol from network layer
    protocol = pkg.protocol if isinstance(pkg, IPv4) else pkg.next_header

    if protocol == Protocol.UDP:
        if len(pkg.data) < 8:
            typer.echo("Warning: UDP datagram too short — skipping.")
            return
        udp = UDP(pkg.data)
        typer.echo(udp)

        if udp.src_port == Port.DNS or udp.dst_port == Port.DNS:
            if len(udp.data) < 12:
                typer.echo("Warning: DNS payload too short — skipping.")
                return
            typer.echo(DNS(udp.data))

        elif udp.src_port in (Port.DHCP_SERVER, Port.DHCP_CLIENT) or udp.dst_port in (
            Port.DHCP_SERVER,
            Port.DHCP_CLIENT,
        ):
            if len(udp.data) < 240:
                typer.echo("Warning: DHCPv4 payload too short — skipping.")
                return
            typer.echo(DHCPv4(udp.data))

        elif udp.src_port in (
            Port.DHCP_V6_CLIENT,
            Port.DHCP_V6_SERVER,
        ) or udp.dst_port in (Port.DHCP_V6_CLIENT, Port.DHCP_V6_SERVER):
            if len(udp.data) < 4:
                typer.echo("Warning: DHCPv6 payload too short — skipping.")
                return
            typer.echo(DHCPv6(udp.data))

    elif protocol == Protocol.TCP:
        if len(pkg.data) < 20:
            typer.echo("Warning: TCP segment too short — skipping.")
            return
        tcp = TCP(pkg.data)
        typer.echo(tcp)

        if tcp.src_port in (Port.HTTP, Port.HTTPS) or tcp.dst_port in (
            Port.HTTP,
            Port.HTTPS,
        ):
            if tcp.data:
                typer.echo(HTTP(tcp.data))

        elif tcp.src_port == Port.NFS or tcp.dst_port == Port.NFS:
            if tcp.data:
                rpc_data = tcp.data[4:] if len(tcp.data) > 4 else tcp.data
                rpc = ONC_RPC(rpc_data)
                typer.echo(rpc)
                if rpc.program == 100003:
                    typer.echo(NFSv4(rpc))

    elif protocol == Protocol.ICMPv4:
        if len(pkg.data) < 8:
            typer.echo("Warning: ICMPv4 segment too short — skipping.")
            return
        typer.echo(ICMPv4(pkg.data))

    elif protocol == Protocol.ICMPv6:
        if len(pkg.data) < 8:
            typer.echo("Warning: ICMPv6 segment too short — skipping.")
            return
        typer.echo(ICMPv6(pkg.data))

    else:
        typer.echo(f"Unsupported transport protocol: {protocol}")


@app.command()
def main(
    file: Annotated[
        Optional[str],
        typer.Argument(help="Raw packet binary file (omit for live capture)"),
    ] = None,
    iface: Annotated[
        Optional[str],
        typer.Option(
            "--iface", "-i", help="Network interface for live capture (e.g., eth0)"
        ),
    ] = None,
    filter: Annotated[
        Optional[str],
        typer.Option("--filter", "-f", help="BPF filter string (e.g., 'tcp port 80')"),
    ] = None,
) -> None:
    # File mode
    if file is not None:
        try:
            with open(file, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            typer.echo(f"Error: file '{file}' not found.", err=True)
            raise typer.Exit(1)
        except OSError as e:
            typer.echo(f"Error reading file: {e}", err=True)
            raise typer.Exit(1)

        parse_and_print(raw)
        return

    # Live capture mode
    if iface is None:
        typer.echo("Error: provide a file path or --iface for live capture.", err=True)
        raise typer.Exit(1)

    def on_packet(pkt) -> None:
        """Scapy callback — convert to raw bytes and pass to the shared parser."""
        try:
            raw = bytes(pkt)
            typer.echo(f"\n{'═' * 50}")
            parse_and_print(raw)
        except Exception as e:
            typer.echo(f"Warning: failed to parse packet — {e}")

    sniffer = AsyncSniffer(
        iface=iface,
        filter=filter,
        prn=on_packet,
        store=False,  # don't accumulate packets in memory
    )

    typer.echo(
        f"Capturing on '{iface}'"
        + (f" with filter '{filter}'" if filter else "")
        + " — press Ctrl+C to stop.\n"
    )

    sniffer.start()

    # Block main thread until Ctrl+C, then stop cleanly
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        typer.echo("\nCapture stopped.")


if __name__ == "__main__":
    app()
