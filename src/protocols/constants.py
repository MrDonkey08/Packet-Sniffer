from enum import IntEnum


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
