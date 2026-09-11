
# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""
desc: This module collects and displays icmp echo reply based on Ip Address.

Functions:

"""

from scapy.all import ICMP, IP, sr1
from rich.console import Console
from datetime import datetime, time
import time
import sys
import json
import os

# Calling the settings.json file to use its contents
try:
    with open("config/settings.json") as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(
        f"Configuration file not found {e}"
    )
    sys.exit(1)

verbose = config["verbose"]
themecolor = config["theme-color"]

console = Console()

def PingScan(Target,
             save=False):

    global verbose, themecolor

    start = time.perf_counter()

    try:
        ip_layer = IP(dst=Target)
        icmp = ICMP()
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

    echo_reply = sr1(ip_layer/icmp, timeout=1, verbose=False)

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
        )

    print(
        f"-{now}"
        )

    print(
        f"-Initiating Pcache scan\n-Pcache scan report for {Target}\n"
        )

    console.print(
        f"Ip Address\tStatus\t\tType", style=themecolor
        )

    if echo_reply is None:
        status = "No response"
        echo_type = "N/A"
    elif echo_reply.haslayer(ICMP):
        echo_type = echo_reply[ICMP].type
        if echo_type == 0:
            status = "Reachable"
        elif echo_type == 3:
            status = "Unreachable"
        elif echo_type == 11:
            status = "FILTERED"
        else:
            status = "FILTERED"
    else:
        status = "FILTERED"
        echo_type = "N/A"

    result = {
        "Target": Target,
        "Status": status,
        "Type": echo_type
    }

    print(
        f"{Target}\t{status}\t{echo_type}"
        )

    elapsed = time.perf_counter() - start
    
    print(
        f"\nScan completed in {elapsed:.2f} seconds"
        )

    # Saving results in a txt file
    if save:

        print()
        file_name = input(
            "File name: "
            ).strip() or "pcache_ping_scan"
        save_path = f"{file_name}.txt"

        try:
            with open(save_path, "w", encoding="utf-8") as txt_file:
                txt_file.write(
                    f"Target\tStatus\tType\n"
                    )
                txt_file.write(
                    f"{result['Target']}\t{result['Status']}\t{result['Type']}\n"
                    )
                print(
                    f"Saved to {os.path.abspath(save_path)}"
                    )
        except OSError as e:
            print(
                f"Failed to save file {e}"
                )

    return result
