
# SPDX-License-identifier: MIT
# Copyright (c) 2026 matar

"""Module docstring here.

desc: This module collects and displays information about the local system and network interface.
It retrieves the system hostname, local IP address, and MAC address.

Functions:
    system_info():
        This function retrieves the hostname, local IP address, and MAC
        address of the system. It then displays the collected information
        in the console.

        If an error occurs while retrieving the system information, the
        error message is displayed.

"""

from scapy.all import get_if_hwaddr, conf
from rich.console import Console
import socket


console = Console()

def SystemInfo():
      
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(socket.gethostname())
        mac_address = get_if_hwaddr(conf.iface)
        
        print(
            f"Hostname:....{hostname}"
            )

        print(
            f"Ip Address:....{local_ip}"
            )

        print(
            f"Mac Address:....{mac_address}"
            )
    except Exception as e:
        print(
            f"Error occurred: {e}"
            )
