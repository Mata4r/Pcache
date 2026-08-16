
# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""Module docstring here.

desc: This module looks up the vendor associated with a MAC address. If the Target is a MAC address, it performs a direct vendor lookup using MacLookup(). If the Target is an IP address, it performs an ARP request to obtain the MAC address before looking up its vendor.

Functions:
    VendorLu():
        This function looks up the vendor associated with the Target.
        If the Target is a valid MAC address, it directly performs a
        vendor lookup using MacLookup().

        If the Target is an IP address, it creates and sends an ARP
        request using Scapy to obtain the MAC address of the target.
        It then uses the MAC address to determine the associated vendor.

        The function can also save the lookup results to a .txt file.

Arguments:
    Target:
        The MAC address or IP address for which the vendor information
        will be retrieved.

    save:
        Determines whether the lookup results should be saved to a
        .txt file.

weakpoint:
    When the Target is an IP address, an ARP request is sent to the
    target. This generates network traffic and requires the target
    device to respond to the ARP request.
        
"""

from scapy.all import Ether, ARP, srp
from scapy.utils import valid_mac
from mac_vendor_lookup import MacLookup
from datetime import datetime
from rich.console import Console
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

def VendorLu(Target,
           save=False):

    global timeout, verbose, themecolor
    
    start = time.perf_counter()
    lookup = MacLookup()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    results = []
    
    if valid_mac(Target):
        # Checking the Vendor through the provided MAC Address 
        try:
            vendor = lookup.lookup(
                Target
                )
        except Exception:
            vendor = "Unknown"

        print(
            f"-{now}"
            )
        print(
            f"-Initiating Ncache scan\n-Ncache scan report for {Target}\n"
            )
        console.print(
            f"Mac Address\t\tVendor", style=themecolor
            )

        print(
            f"{Target}\t{vendor}"
            )
        
        # Save the results in results[]
        results.append((
            Target, 
            vendor
            ))

        elapsed = time.perf_counter() - start
        print(
            f"\nScan completed in {elapsed:.2f} seconds\n"
            )
    else:
        # else will run if the input was IP Address
        start = time.perf_counter()

        # Building an ARP packet in preparation for its use in ARP sweeping
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=Target)

        # Sending and receiving ARP resluts at layer 2
        try:
            answered, unanswered = srp(ether / arp,
                                       timeout=timeout,
                                       verbose=verbose,
                                       retry=1)
        except Exception as e:
            print(
                f"Error{e}"
                )

        print(
            f"-{now}"
            )
        
        print(
            f"-Initiating Ncache scan\n-Ncache scan report for {Target}\n"
            )
        
        console.print(
            f"Mac Address\t\tVendor", style=themecolor
            )

        # Display the results that have been received from the ARP sweeping
        for sent, recv in answered:
            # Checking the vendor through the MAC address in recv 
            try:
                vendor = lookup.lookup(
                    recv.hwsrc
                    )
            except Exception:
                vendor = "Unknown"
            
            print(
                f"{recv.hwsrc}\t{vendor}"
                )

            # Save the results in results[]
            results.append((recv.hwsrc, 
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
                    f"Mac Address       Vendor\n"
                    )
                
                for mac, vendor in results:
                    txt_file.write(
                        f"{mac} {vendor}\n"
                        )
                print(
                    f"Saved to {os.path.abspath(file_name)}.txt"
                    )
        except OSError as e:
            print(
                f"Failed to save file {e}"
                )
