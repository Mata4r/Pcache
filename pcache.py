#!/usr/bin/env python3

import argparse

from modules.pcache_arp_scan import ArpProcessor
from modules.pcache_passive_scan import PassiveScan
from modules.pcache_system_info import SystemInfo
from modules.pcache_vendor_scan import VendorLu


def main():

    parser = argparse.ArgumentParser(
        description="Pcatch Network Scanner"
        )

    parser.add_argument(
        "-As", action="store_true", help="Scans Using ARP"
        )
    
    parser.add_argument(
        "-Ps", action="store_true", help="Scans Passively"
        )
    
    parser.add_argument(
        "-V", action="store_true", help="Get vendor"
        )
    
    parser.add_argument(
        "-info", action="store_true", help="Get System info"
        )
    
    parser.add_argument(
        "-save", action="store_true", help="Save results"
        )

    parser.add_argument(
        "-T00", action="store_true", help="~1 Hour for a default /24 scan"
        )
    
    parser.add_argument(
        "-T0", action="store_true", help="~20 Min for a default /24 scan"
        )
    
    parser.add_argument(
        "-T1", action="store_true", help="~10 Min for a default /24 scan"
        )
    
    parser.add_argument(
        "-T2", action="store_true", help="~5 Min for a default /24 scan"
        )
    
    parser.add_argument(
        "-T3", action="store_true", help="~25 Sec for a default /24 scan"
        )
    
    parser.add_argument(
        "-T4", action="store_true", help="~5 Sec for a default /24 scan"
        )

    parser.add_argument(
        "-i", "--interface", default=None, help="Input interface"
        )
    
    parser.add_argument(
        "Target", nargs="?", help="Input Target"
        )

    args = parser.parse_args()
    

    try:
        if args.As:
            if not args.Target:
                raise ValueError(
                    "Subnet is required for ARP scan"
                    )

            ArpProcessor(
                args.Target,
                args.save,
                args.T00,
                args.T0,
                args.T1,
                args.T2,
                args.T3,
                args.T4
            )


        elif args.Ps:
            if not args.Target or not args.interface:
                raise ValueError(
                    "Subnet & interface is required for passive scan"
                    )

            PassiveScan(
                args.Target,
                args.interface,
                args.save
            )


        elif args.info:
            SystemInfo()


        elif args.V:
            if not args.Target:
                raise ValueError(
                    "MAC address or target is required for vendor lookup"
                    )

            VendorLu(
                args.Target,
                args.save
            )

    except Exception as e:
        print(
            f"Error occurred: {e}"
            )

if __name__ == "__main__":
    main()
