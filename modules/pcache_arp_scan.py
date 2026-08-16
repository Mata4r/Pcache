
# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""Module docstring here.

desc: This module performs an ARP scan on the network to collect information about netwrok devices.

Functions:
    ArpProcessor():
        This function creates an Ethernet frame and ARP packet,
        which are sent to the target using Scapy srp() function,
        It receives ARP responses and extracts the IP address, MAC address,
        and vendor of each discovered device.

Arguments:
    Target:
        The target network or IP address to scan.
    save:
        Determines whether the scan results should be saved to a
        .txt file.
    T00:
        Uses the slowest scan interval.
    T0:
        Uses a slower scan interval.
    T1:
        Uses a moderate scan interval.
    T2:
        Uses a faster scan interval.
    T3:
        Uses a very fast scan interval.
    T4:
        Sends packets with no interval between them.
        
"""

from scapy.all import Ether, ARP, srp 
from mac_vendor_lookup import MacLookup
from rich.console import Console
from datetime import datetime
import time
import os
import json

console = Console()

# Calling the settings.json file to use its contents
with open("config/settings.json") as f:
    config = json.load(f)

timeout = config["timeout"]
verbose = config["verbose"]
themecolor = config["theme-color"]

def ArpProcessor(Target,
                  save=False,
                  T00=False,
                  T0=False,
                  T1=False,
                  T2=False,
                  T3=False,
                  T4=False):
    
    global timeout, verbose, themecolor
    
    start = time.perf_counter()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
        )

    results = []

    if T00:
        scan_time = 14.2
    elif T0:
        scan_time = 4.7
    elif T1:
        scan_time = 2.4
    elif T2:
        scan_time = 1.2
    elif T3:
        scan_time = 0.1
    elif T4:
        scan_time = 0
    else:
        scan_time = 0.0

    if scan_time is not None:
        # Building an ARP packet in preparation for its use in ARP sweeping
        try:
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=Target)

            # Sending and receiving ARP resluts at layer 2
            answered, unanswered = srp(ether/arp,
                                       timeout=timeout,
                                       verbose=verbose,
                                       inter=scan_time
                                      )
        except Exception as e:
            print(
                f"Error occurred: {e}"
                )
            return
            
        lookup = MacLookup()

        print(
            f"-{now}"
            )
        
        print(
            f"-Initiating Ncache scan\n-Ncache scan report for {Target}\n"
            )
        
        console.print(
            "IP Address\tMAC Address\t    Vendor",style=themecolor
            )

        # Display the results that have been received from the ARP sweeping
        for sent, recv in answered:
            # Checking the vendor through the MAC address as a result of analyzing the layer 2 packet
            try:
                vendor = lookup.lookup(
                    recv.hwsrc
                    )
            except Exception:
                vendor = "Unknown"

            print(
                f"{recv.psrc}\t{recv.hwsrc}   {vendor}"
                )

            # Save the results in results{}
            results.append((
                recv.psrc,
                  recv.hwsrc,
                    vendor))
                
    elapsed = time.perf_counter() - start
    
    print(
        f"\nScan completed in {elapsed:.2f} seconds"
        )

    # Saving results in a .txt file
    if save:

        print()
        file_name = input(
            "File name: "
            )

        try:

            with open(f"{file_name}.txt", "w") as txt_file:
                txt_file.write(
                    "IP Address\t\t    MAC Address\t        Vendor\n"
                    )

                for ip, mac, vendor in results:
                    txt_file.write(
                        f"{ip}\t\t{mac}   {vendor}\n"
                        )
                    
                print(
                    f"Saved to {os.path.abspath(file_name)}.txt"
                    )
        except OSError as e:
            print(
                f"Failed to save file {e}"
                )
