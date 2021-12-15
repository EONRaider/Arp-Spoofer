#!/usr/bin/env python3
# https://github.com/EONRaider/Arp-Spoofer

__author__ = "EONRaider @ keybase.io/eonraider"

import PyInstaller.__main__ as pyinstaller


def build() -> None:
    """Set up the arguments required by PyInstaller to build the ARP
    Spoofer binary."""
    pyinstaller.run(("src/arpspoof.py", "--onefile"))


if __name__ == "__main__":
    build()
