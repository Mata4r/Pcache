# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""
desc: This module performs a Passive discovery on the network it collects information about connected devices

Functions:
    PassiveScan():
        This function starts sniffing the network using Scapy's sniff()
        function. It provides captured packets to packet_processor()
        to be analyzed and recognized. It can also save the collected
        device information to a .txt file.
    packet_processor():
        This function analyzes and identifies network packets captured
        by the passive scanner. It extracts IP addresses and MAC
        addresses from IP, Ethernet, and ARP packets, checks whether
        the IP address belongs to the Target network, and identifies
        the MAC address vendor.

Arguments:
    Target:
        The target network that passive discovery monitors.

    interface:
        The network interface used by Scapy to capture packets.

    save:
        Determines whether the collected results should be saved
        to a .txt file.

weakpoint: Passive discovery might not collect information about silent
           clients that are not generating network traffic during the scan.
"""

from scapy.all import sniff, IP, Ether, ARP
from scapy.error import Scapy_Exception
from mac_vendor_lookup import MacLookup
from rich.console import Console
from datetime import datetime
import ipaddress
import sys
import os
import json

console = Console()
lookup = MacLookup()

try:
    with open("config/settings.json") as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(
        f"Configuration file not found: {e}"
    )
    sys.exit(1)
except json.JSONDecodeError as e:
    print(
        f"Configuration file is not valid JSON: {e}"
    )
    sys.exit(1)

themecolor = config.get("theme-color", "cyan")

results = {}
seen_macs = {}


def get_vendor(mac_address):

    first_byte = int(mac_address.split(":")[0], 16)

    if first_byte & 0x02:
        return "Randomized MAC"

    try:
        return lookup.lookup(
            mac_address
            )
    except Exception:
        return "Unknown"


def packet_processor(network,
                     packet):

    if ARP in packet:

        if packet[ARP].op not in (1, 2):
            return

        ip_address = packet[ARP].psrc
        mac_address = packet[ARP].hwsrc
    elif IP in packet and Ether in packet:

        ip_address = packet[IP].src
        mac_address = packet[Ether].src
    else:
        return

    try:
        ip_object = ipaddress.ip_address(ip_address)
    except ValueError:
        return

    if ip_object not in network:
        return

    if ip_object.is_unspecified or ip_object.is_multicast:
        return

    if network.prefixlen < 31 and ip_object == network.broadcast_address:
        return

    if ip_address not in results:

        vendor = get_vendor(
            mac_address
            )

        results[ip_address] = (
            mac_address,
            vendor
            )

        seen_macs[ip_address] = {mac_address}

        print(
            f"{ip_address:<16}{mac_address:<19}{vendor}"
            )
        return

    old_mac = results[ip_address][0]

    if old_mac != mac_address:

        if mac_address not in seen_macs[ip_address]:

            seen_macs[ip_address].add(mac_address)

            console.print(
                f"[!] {ip_address} changed MAC {old_mac} -> {mac_address}",
                style="bold yellow",
                markup=False,
                highlight=False
                )

        results[ip_address] = (
            mac_address,
            get_vendor(
                mac_address
                )
            )


def save_results():

    if not results:

        print(
            "Nothing to save."
            )
        return

    try:
        file_name = input(
            "File name: "
            ).strip() or "scan_results"
    except (EOFError, KeyboardInterrupt):

        print(
            "\nSave cancelled."
            )
        return

    file_name = os.path.basename(file_name)
    path = f"{file_name}.txt"

    if os.path.exists(path):

        stamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
            )
        path = f"{file_name}_{stamp}.txt"

    try:
        with open(path, "x") as txt_file:
            txt_file.write(
                f"{'IP Address':<16}{'MAC Address':<19}Vendor\n"
                )

            for ip, (mac, vendor) in sorted(
                results.items(),
                key=lambda item: ipaddress.ip_address(item[0])
                ):
                txt_file.write(
                    f"{ip:<16}{mac:<19}{vendor}\n"
                    )

        print(
            f"Saved to {os.path.abspath(path)}"
            )
    except OSError as e:
        print(
            f"Failed to save file {e}"
            )


def PassiveScan(Target,
                interface,
                save=False,
                store=False):

    try:
        network = ipaddress.ip_network(Target,
                                       strict=False)
    except ValueError as e:
        print(
            f"Invalid target network: {e}"
            )
        return

    if network.version != 4:

        print(
            "Only IPv4 networks are supported."
            )
        return

    results.clear()
    seen_macs.clear()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
        )

    print(
        "Listening..."
        )

    print(
        "Press Ctrl+C to stop.\n"
        )

    print(
        f"-{now}"
        )

    print(
        f"-Initiating Pcache scan\n-Pcache scan report for {Target}\n"
        )

    console.print(
        f"{'IP address':<16}{'MAC address':<19}Vendor", style=themecolor
        )

    try:
        while True:
            sniff(iface=interface,
                  filter="arp or ip",
                  prn=lambda pkt: packet_processor(network, pkt),
                  store=store,
                  timeout=1)
    except KeyboardInterrupt:
        print()
    except PermissionError:
        print(
            "Permission denied, run as administrator or root."
            )
    except (Scapy_Exception, OSError) as e:
        print(
            f"Capture failed on {interface}: {e}"
            )

    print(
        f"{len(results)} device(s) found"
        )

    if save:

        print()
        save_results()

    return results
