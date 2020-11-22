#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'


import re
from ctypes import *
from socket import inet_aton


class Packet(object):
    def __init__(self, *protocols):
        valid_protocols = (cls.__name__ for cls in Protocol.__subclasses__())
        for protocol in protocols:
            protocol_name = protocol.__class__.__name__
            if protocol_name not in valid_protocols:
                raise AttributeError('Cannot build packet. Invalid protocol: {}'
                                     .format(protocol_name))
            setattr(self, protocol_name.lower(), protocol)

    def __bytes__(self):
        return b''.join(proto for proto in self.__dict__.values())

    @property
    def payload(self):
        return self.__bytes__()


class Protocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self):
        super().__init__()

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @staticmethod
    def hdwr_addr_to_array(mac_addr: str):
        """
        Converts a IEEE 802 MAC address to c_ubyte array of 6 bytes.
        """
        mac_to_bytes = b''.join(bytes.fromhex(octet)
                                for octet in re.split('[:-]', mac_addr))
        return (c_ubyte * 6)(*mac_to_bytes)

    @staticmethod
    def proto_addr_to_array(proto_addr: str):
        """
        Converts a dotted-quad formatted IPv4 address string to a
        c_ubyte array of 6 bytes.
        """
        addr_to_bytes = inet_aton(proto_addr)
        return (c_ubyte * 4)(*addr_to_bytes)


class Ethernet(Protocol):      # IEEE 802.3 standard
    _fields_ = [
        ('dst', c_ubyte * 6),  # Destination hardware address
        ('src', c_ubyte * 6),  # Source hardware address
        ('eth', c_uint16)      # Ethertype
    ]

    def __init__(self, *, dst: str, src: str, eth: int):
        super().__init__()
        self.dst = self.hdwr_addr_to_array(dst)
        self.src = self.hdwr_addr_to_array(src)
        self.eth = int(eth)


class ARP(Protocol):           # IETF RFC 826
    _fields_ = [
        ("htype", c_uint16),   # Hardware type
        ("ptype", c_uint16),   # Protocol type
        ("hlen", c_uint8),     # Hardware length
        ("plen", c_uint8),     # Protocol length
        ("oper", c_uint16),    # Operation
        ("sha", c_ubyte * 6),  # Sender hardware address
        ("spa", c_ubyte * 4),  # Sender protocol address
        ("tha", c_ubyte * 6),  # Target hardware address
        ("tpa", c_ubyte * 4),  # Target protocol address
    ]

    def __init__(self, *, sha: str, spa: str, tha: str, tpa: str):
        super().__init__()
        self.htype = self.ETHERNET
        self.ptype = self.IPV4
        self.hlen = self.ETHERNET_ADDR_LEN
        self.plen = self.IPV4_ADDR_LEN
        self.oper = self.REPLY
        self.sha = self.hdwr_addr_to_array(sha)
        self.spa = self.proto_addr_to_array(spa)
        self.tha = self.hdwr_addr_to_array(tha)
        self.tpa = self.proto_addr_to_array(tpa)
