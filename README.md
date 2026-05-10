# Packet Sniffer

[![en](https://img.shields.io/badge/lang-en-red.svg)](./README.md)
[![es](https://img.shields.io/badge/lang-es-blue.svg)](./README.es.md)

## Table of Contents

<!--toc:start-->

- [Packet Sniffer](#packet-sniffer)
  - [Table of Contents](#table-of-contents)
  - [About](#about)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Clone the Repository](#clone-the-repository)
    - [Install Dependencies](#install-dependencies)
  - [Usage](#usage)
    - [File Mode](#file-mode)
    - [Live Capture Mode](#live-capture-mode)
    - [Option Reference](#option-reference)
  - [Assumptions](#assumptions)
  - [Important Notes](#important-notes)
  <!--toc:end-->

## About

Network packet sniffer written in Python that allows you to capture and dissect
live traffic from a network interface, or analyze a binary file of previously
captured packets.

The analyzer breaks down packets layer by layer according to the OSI model:

| Layer            | Supported protocols                           |
| ---------------- | --------------------------------------------- |
| Data Link (L2)   | Ethernet II, 802.1Q VLAN, ARP                 |
| Network (L3)     | IPv4, IPv6                                    |
| Transport (L4)   | TCP, UDP, ICMPv4, ICMPv6                      |
| Application (L7) | DNS, DHCPv4, DHCPv6, HTTP/1.x, ONC RPC, NFSv4 |

## Installation

### Prerequisites

- Python 3.10 or later (type annotations `X | Y` are used)
- Superuser privileges for live capture (`CAP_NET_RAW`)
- [`uv`](https://docs.astral.sh/uv/) as an environment and dependency manager

### Clone the Repository

```bash
git clone https://github.com/MrDonkey08/packet-sniffer.git
cd packet-sniffer
```

> [!TIP]
>
> You can add the option `--depth=1` to `git clone` to only clone the latest
> commit.

### Install Dependencies

```bash
uv sync
```

The project's dependencies are declared in `pyproject.toml`. The main ones are:

- [`scapy`](https://scapy.net/) — asynchronous live packet capture
- [`typer`](https://typer.tiangolo.com/) — command-line interface

## Usage

The entry point is `src/main.py` and can be executed either with `uv run`
(recommended), `python3` or directly (e.g., `src/main.py`).

There are two modes of operation:

- [File Mode](#file-mode)
- [Live Capture Mode](#live-capture-mode)

### File Mode

Analyzes a binary file containing a single raw Ethernet frame:

```bash
uv run src/main.py <file>
```

```bash
# e.g., analyze a previously captured frame
uv run src/main.py captures/dns_query.bin
```

### Live Capture Mode

Captures packets in real time on a network interface:

```bash
sudo uv run src/main.py --iface <interface>
```

Can be combined with a BPF filter using `--filter` / `-f`:

```bash
# e.g., capture only DNS traffic on eth0
sudo uv run src/main.py --iface eth0 --filter “udp port 53”

# e.g., capture TCP traffic on port 80 or 443
sudo uv run src/main.py -i eth0 -f “tcp port 80 or tcp port 443”
```

Pressing `Ctri + C` stops the capture cleanly.

### Option Reference

```console
$ uv run src/main.py --help

 Usage: main.py [OPTIONS] [FILE]

╭─ Arguments ──────────────────────────────────────────────────────────────────────────╮
│   file      [FILE]  Raw packet binary file (omit for live capture)                   │
╰──────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────╮
│ --iface               -i      TEXT  Network interface for live capture (e.g., eth0)  │
│ --filter              -f      TEXT  BPF filter string (e.g., 'tcp port 80')          │
│ --install-completion                Install completion for the current shell.        │
│ --show-completion                   Show completion for the current shell, to copy   │
│                                     it or customize the installation.                │
│ --help                              Show this message and exit.                      │
╰──────────────────────────────────────────────────────────────────────────────────────
```

## Assumptions

- The input binary files contain exactly one complete Ethernet II frame,
  including the 4-byte FCS at the end (although Wireshark usually omits it in
  captures).

- In live captures, Scapy provides the frames without the FCS; the parser
  handles this correctly when calculating the payload offsets.

- The EtherType field is used to determine the network protocol. Frames with
  unrecognized EtherTypes (i.e., other than `0x0800`, `0x86DD`, `0x0806`) are
  reported but not analyzed in depth.

- Application protocol detection is based exclusively on the port number (e.g.,
  port 53 → DNS, port 80/443 → HTTP). No deep payload inspection is performed to
  infer the protocol.

- For NFS, it is assumed that TCP messages carry a 4-byte record length prefix
  (record marking, RFC 5531 §11) that is discarded before parsing the RPC.

- Double-tagged 802.1Q frames (QinQ, EtherType `0x88A8`) are not supported.

## Important Notes

- **Privileges**: Live capture requires running the script as root or with the
  `CAP_NET_RAW` capability. On Linux, this can be granted with:

  ```bash
  sudo setcap cap_net_raw+eip $(which python3)
  ```

- **IP Fragmentation**: IP fragments other than the first one (fragment offset
  ≠ 0) lack a transport header. The parser will attempt to parse the payload as
  a transport protocol and fail silently; no reassembly is performed.

- **Encrypted HTTP**: The HTTP/1.x parser operates on plain text. HTTPS traffic
  (`port 443`) will appear as uninterpretable binary data in the body field.

- **Parsing errors**: Malformed or truncated packets generate warnings on
  _stdout_, but do not halt execution. Layers that cannot be parsed display the
  bytes in hexadecimal as a fallback.

- **IPv6 Extension Headers**: IPv6 extension headers (e.g., Hop-by-Hop, Routing,
  Fragment) are not parsed; the `next_header` field is reported with its numeric
  value, and the payload is treated directly as the specified transport
  protocol.
