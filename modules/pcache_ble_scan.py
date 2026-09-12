# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""
desc: This module performs Bluetooth device discovery using the Bleak
      library. It scans for nearby Bluetooth devices and collects
      information including device names, Bluetooth addresses, and
      RSSI signal strength. The results can be displayed in a formatted
      table and optionally saved to a .txt file.

Functions:
    scan_bluetooth_devices():
        This asynchronous function scans for nearby Bluetooth devices
        using BleakScanner.discover(). It displays the discovered
        devices and their information in a Rich table. It can also
        continuously scan at a specified interval and save the collected
        device information to a .txt file.

Arguments:
    save:
        Determines whether the collected Bluetooth device information
        should be saved to a .txt file.

    live:
        Determines whether the scanner continuously performs Bluetooth
        scans until the user stops it with Ctrl+C.

    interval:
        Specifies the amount of time in seconds to wait between scans
        when live scanning is enabled.

weakpoint: Bluetooth discovery might not detect devices that are out of
           range, not discoverable, powered off, or not responding to
           Bluetooth discovery requests. RSSI values may also vary
           depending on distance and environmental conditions.
"""

import asyncio
import os
from bleak import BleakScanner
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console(width=140)

async def scan_bluetooth_devices(save=False, live=False, interval=5.0):
    save_path = None

    if save:
        print()
        file_name = input(
            "File name: "
            ).strip() or "pcache_ble_scan"
        save_path = f"{file_name}.txt"

    while True:
        try:
            devices = await BleakScanner.discover(
                timeout=5.0, return_adv=True
                )

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            console.clear()
            print(
                f"-{now}"
                )
            print(
                "-Scanning for Bluetooth devices...\n"
                )
            if live:
                print(
                    "-Press Ctrl+C to stop.\n"
                    )

            table = Table(
                title="Bluetooth Devices"
                )
            table.add_column("Device", style="bold magenta", min_width=20, max_width=35)
            table.add_column("Address", style="bold magenta", min_width=18, max_width=30)
            table.add_column("RSSI", justify="right", style="green", min_width=8, max_width=12)

            results = []

            for address, (device, adv) in devices.items():
                if device.name is None:
                    device_name = "Unknown"
                else:
                    device_name = device.name

                table.add_row(device_name, address, str(adv.rssi))
                results.append((device_name, address, adv.rssi))

            console.print(table)

            if save and save_path:
                try:
                    with open(save_path, "w", encoding="utf-8") as txt_file:
                        txt_file.write(
                            "Device\tAddress\tRSSI\n"
                            )
                        for device_name, address, rssi in results:
                            txt_file.write(
                                f"{device_name}\t{address}\t{rssi}\n"
                                )
                    print(
                        f"Saved to {os.path.abspath(save_path)}"
                        )
                except OSError as e:
                    print(
                        f"Failed to save file {e}"
                        )

            if not live:
                break

            await asyncio.sleep(interval)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\nBluetooth scan stopped.")
            break
        except Exception as e:
            print(
                f"error occurred: {e}"
                )
            if not live:
                break
            await asyncio.sleep(interval)
              
