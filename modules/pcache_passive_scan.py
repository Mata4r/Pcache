
# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""Module docstring here."""

"""

desc: This module performs an Passive discovery on the network it collects information about connected devices

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
from mac_vendor_lookup import MacLookup
from rich.console import Console
from datetime import datetime
import ipaddress
import os
import json

console = Console()

# Calling the settings.json file to use its contents
with open("config/settings.json") as f:
    config = json.load(f)

themecolor = config["theme-color"]

results = {}

def packet_processor(Target,
                    packet):

    # Analyzing the packet to get the IP Address and the MAC Address from layer 3 & layer 2
    if IP in packet and Ether in packet:

        ip_address = packet[IP].src
        mac_address = packet[Ether].src   
    elif ARP in packet:

        ip_address = packet[ARP].psrc
        mac_address = packet[ARP].hwsrc
    else:
        return

    network = ipaddress.ip_network(Target,
                                   strict=False)

    # Check if IP Address is a network object
    try:
        if ipaddress.ip_address(ip_address) not in network:

            return
    except ValueError:
        return

    lookup = MacLookup()

    # Checks if a IP Address not in results{} to forbid printing the same IP Address again
    if ip_address not in results:
        # Checking the Vendor through the MAC Address as a result of analyzing the layer 2 packet
        try:
            vendor = lookup.lookup(
                mac_address
                )
        except Exception:
            vendor = "Unknown"

        # Save the results in results{}
        results[ip_address] = (
            mac_address, 
            vendor
            )
        
        print(
            f"{ip_address}\t{mac_address}   {vendor}"
            )

# The main function to network sniffing
def PassiveScan(Target,
                       interface,
                       save=False):

    global store, themecolor

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
        f"-Initiating Ncache scan\n-Ncache scan report for {Target}\n"
        )
    
    console.print(
        "IP address\tMac Address\t    Vendor", style=themecolor
        )

    try:
        # Scapy sniff() function to start a live packet sniffing and leading every packet to packet_processor() function
        result = sniff(iface=interface,
                       prn=lambda pkt: packet_processor(Target, pkt),
                       store=False)
    except KeyboardInterrupt:
        print()
    

    # Saving results in a .txt file 
    if save:
        
        print()
        file_name = input(
            "File name: "
            )

        try:
            with open(f"{file_name}.txt", "w") as txt_file:
                txt_file.write(
                    "IP Address\t    MAC Address\t        Vendor\n"
                    )

                for ip, (mac, vendor) in results.items():
                    txt_file.write(
                        f"{ip}\t{mac}   {vendor}\n"
                        )
                print(
                    f"Saved to {os.path.abspath(file_name)}.txt"
                    )
        except OSError  as e:
            print(
                f"Failed to save file {e}"
                )
