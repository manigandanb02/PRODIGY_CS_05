from scapy.all import conf, sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.packet import Raw

from colorama import Fore, Style, init
from collections import Counter
from datetime import datetime
import csv
import os


packet_count = 0
protocol_counter = Counter()
captured_packets = []
capture_start = None

init(autoreset=True)


def show_banner():
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "                 PacketSleuth - Network Packet Analyzer")
    print(Fore.WHITE + "                     Version 1.0 | CLI Edition")
    print(Fore.CYAN + "=" * 70)

    print(Fore.YELLOW + Style.BRIGHT + "\n                 Educational & Authorized Use Only\n")

    print("This tool captures and analyzes network packets from")
    print("the selected network interface.")
    print()
    print("Use this tool only on networks that you own or have")
    print("explicit permission to monitor.")
    print()
    print("Unauthorized packet capturing may violate privacy")
    print("laws and organizational security policies.")

    print(Fore.CYAN + "\n" + "=" * 70)
    print()
    print(Fore.GREEN + "[✓] Initializing PacketSleuth")
    print(Fore.GREEN + "[✓] Loading network interfaces")
    print(Fore.GREEN + "[✓] Ready to capture packets")
    print()


def select_interface():
    interfaces = []

    for iface in conf.ifaces.values():
        name = iface.description.lower()

        if (
            "wan miniport" in name
            or "wi-fi direct" in name
            or "bluetooth" in name
        ):
            continue

        interfaces.append(iface)

    print()
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "Available Network Interfaces")
    print(Fore.CYAN + "=" * 70)

    print(f"{'No':<4}{'Interface Name':<55}{'Type'}")
    print("-" * 75)

    for i, iface in enumerate(interfaces, start=1):
        description = iface.description
        lower_desc = description.lower()

        if "virtualbox" in lower_desc:
            iface_type = "Virtual"
        elif "loopback" in lower_desc:
            iface_type = "Loopback"
        elif "wifi" in lower_desc or "wi-fi" in lower_desc:
            iface_type = "Wireless"
        elif "ethernet" in lower_desc or "family controller" in lower_desc:
            iface_type = "Ethernet"
        else:
            iface_type = "Network"

        print(f"{i:<4}{description:<55}{iface_type}")

    recommended = None

    for i, iface in enumerate(interfaces):
        name = iface.description.lower()

        if "wifi" in name or "wi-fi" in name:
            recommended = i + 1
            break
        elif "family controller" in name or "ethernet" in name:
            recommended = i + 1

    while True:
        if recommended:
            print(
                Fore.YELLOW
                + f"\nRecommended: {interfaces[recommended - 1].description}"
            )

        try:
            choice = int(input("\nSelect an interface: "))

            if 1 <= choice <= len(interfaces):
                selected = interfaces[choice - 1]
                print(Fore.GREEN + f"\n[✓] Selected Interface: {selected.description}\n")
                return selected

            print(Fore.RED + "Invalid selection. Try again.")

        except ValueError:
            print(Fore.RED + "Please enter a valid number.")


def select_filter():
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "Capture Filter")
    print(Fore.CYAN + "=" * 70)

    print("1. All Packets")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")
    print("5. DNS")
    print("6. Custom IP")
    print("7. Custom Port")
    print("0. Exit")

    print(Fore.CYAN + "=" * 70)

    while True:
        choice = input("Select a filter: ")

        if choice == "1":
            return {"name": "All Packets", "filter": ""}

        elif choice == "2":
            return {"name": "TCP", "filter": "tcp"}

        elif choice == "3":
            return {"name": "UDP", "filter": "udp"}

        elif choice == "4":
            return {"name": "ICMP", "filter": "icmp"}

        elif choice == "5":
            return {"name": "DNS", "filter": "port 53"}

        elif choice == "6":
            ip = input("Enter IP Address: ").strip()
            return {"name": f"IP ({ip})", "filter": f"host {ip}"}

        elif choice == "7":
            port = input("Enter Port: ").strip()

            if port.isdigit():
                return {"name": f"Port ({port})", "filter": f"port {port}"}

            print(Fore.RED + "Invalid port.")

        elif choice == "0":
            print(Fore.YELLOW + "\nExiting PacketSleuth...")
            exit()

        else:
            print(Fore.RED + "Invalid choice. Try again.")


def confirm_capture(interface, capture_filter):
    print()
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "Capture Configuration")
    print(Fore.CYAN + "=" * 70)

    print(f"Interface : {interface.description}")
    print(f"Filter    : {capture_filter['name']}")

    print(Fore.CYAN + "=" * 70)

    while True:
        choice = input("\nStart packet capture? (Y/N): ").strip().lower()

        if choice == "y":
            print(Fore.GREEN + "\n[✓] Starting packet capture...\n")
            return True

        elif choice == "n":
            print(Fore.YELLOW + "\nCapture cancelled.")
            return False

        else:
            print(Fore.RED + "Please enter Y or N.")


def decode_packet(packet):
    data = {
        "source_ip": "-",
        "destination_ip": "-",
        "protocol": "Unknown",
        "source_port": "-",
        "destination_port": "-",
        "length": len(packet),
        "payload_hex": "No Payload"
    }

    if IP in packet:
        data["source_ip"] = packet[IP].src
        data["destination_ip"] = packet[IP].dst

    elif IPv6 in packet:
        data["source_ip"] = packet[IPv6].src
        data["destination_ip"] = packet[IPv6].dst

    elif ARP in packet:
        data["source_ip"] = packet[ARP].psrc
        data["destination_ip"] = packet[ARP].pdst
        data["protocol"] = "ARP"
        return data

    if TCP in packet:
        data["protocol"] = "TCP"
        data["source_port"] = packet[TCP].sport
        data["destination_port"] = packet[TCP].dport

    elif UDP in packet:
        data["protocol"] = "UDP"
        data["source_port"] = packet[UDP].sport
        data["destination_port"] = packet[UDP].dport

        if DNS in packet:
            data["protocol"] = "DNS"

    elif ICMP in packet:
        data["protocol"] = "ICMP"

    if Raw in packet:
        raw_data = bytes(packet[Raw].load)
        data["payload_hex"] = raw_data[:32].hex(" ")

    return data


def packet_callback(packet):
    global packet_count

    packet_count += 1

    decoded = decode_packet(packet)
    decoded["time"] = datetime.now().strftime("%H:%M:%S")

    protocol_counter[decoded["protocol"]] += 1
    captured_packets.append(decoded)

    print(
        f"{packet_count:<5}"
        f"{decoded['time']:<11}"
        f"{decoded['protocol']:<8}"
        f"Length: {decoded['length']}"
    )

    print(f"    Source IP      : {decoded['source_ip']}")
    print(f"    Destination IP : {decoded['destination_ip']}")
    print("-" * 70)


def capture_packets(interface, capture_filter):
    global capture_start

    capture_start = datetime.now()

    print(f"{'No':<5}{'Time':<11}{'Proto':<8}{'Length'}")
    print("-" * 70)

    try:
        sniff(
            iface=interface,
            filter=capture_filter["filter"],
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\nStopping packet capture...")

    finally:
        show_capture_summary()


def export_to_csv():
    if not captured_packets:
        print(Fore.YELLOW + "\nNo packets available to export.")
        return

    os.makedirs("captures", exist_ok=True)

    filename = datetime.now().strftime(
        "captures/capture_%Y%m%d_%H%M%S.csv"
    )

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Packet No",
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Length (Bytes)"
        ])

        for index, packet in enumerate(captured_packets, start=1):
            writer.writerow([
                index,
                packet["time"],
                packet["source_ip"],
                packet["destination_ip"],
                packet["protocol"],
                packet["length"]
            ])

    print(Fore.GREEN + f"\n[✓] CSV exported successfully.")
    print(Fore.GREEN + f"[✓] Saved to: {filename}")


def generate_report():
    if not captured_packets:
        return

    os.makedirs("reports", exist_ok=True)

    filename = datetime.now().strftime(
        "reports/report_%Y%m%d_%H%M%S.txt"
    )

    duration = datetime.now() - capture_start
    seconds = int(duration.total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    with open(filename, "w", encoding="utf-8") as file:
        file.write("=" * 70 + "\n")
        file.write("PacketSleuth - Network Packet Analyzer Report\n")
        file.write("=" * 70 + "\n\n")

        file.write(f"Generated On     : {datetime.now()}\n")
        file.write(f"Capture Duration : {hours:02}:{minutes:02}:{seconds:02}\n")
        file.write(f"Total Packets    : {packet_count}\n\n")

        file.write("Protocol Distribution\n")
        file.write("-" * 30 + "\n")

        protocol_order = ["TCP", "UDP", "DNS", "ICMP", "ARP", "Unknown"]

        for protocol in protocol_order:
            if protocol in protocol_counter:
                file.write(f"{protocol:<10}: {protocol_counter[protocol]}\n")

        for protocol, count in protocol_counter.items():
            if protocol not in protocol_order:
                file.write(f"{protocol:<10}: {count}\n")

        file.write("\n")
        file.write("=" * 70 + "\n")
        file.write("Packet Details\n")
        file.write("=" * 70 + "\n\n")

        for index, packet in enumerate(captured_packets, start=1):
            file.write(f"Packet #{index}\n")
            file.write("-" * 40 + "\n")

            file.write(f"Time              : {packet['time']}\n")
            file.write(f"Protocol          : {packet['protocol']}\n\n")

            file.write(f"Source IP         : {packet['source_ip']}\n")
            file.write(f"Destination IP    : {packet['destination_ip']}\n\n")
            
            if packet["source_port"] != "-" or packet["destination_port"] != "-":
                file.write(f"Source Port       : {packet['source_port']}\n")
                file.write(f"Destination Port  : {packet['destination_port']}\n\n")

            file.write(f"Packet Length     : {packet['length']} bytes\n\n")

            file.write("Payload Preview (First 32 Bytes)\n")
            file.write("-" * 40 + "\n")
            file.write(packet["payload_hex"] + "\n\n")

            file.write("=" * 70 + "\n\n")

    print(Fore.GREEN + f"[✓] Report saved to: {filename}")


def show_capture_summary():
    duration = datetime.now() - capture_start

    print()
    print(Fore.CYAN + "=" * 70)
    print(Fore.GREEN + Style.BRIGHT + "Capture Summary")
    print(Fore.CYAN + "=" * 70)

    seconds = int(duration.total_seconds())
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(f"Capture Duration : {hours:02}:{minutes:02}:{seconds:02}")
    print(f"Total Packets    : {packet_count}")

    print("\nProtocol Distribution")
    print("-" * 35)

    if protocol_counter:
        protocol_order = ["TCP", "UDP", "DNS", "ICMP", "ARP", "Unknown"]

        for protocol in protocol_order:
            if protocol in protocol_counter:
                print(f"{protocol:<10}: {protocol_counter[protocol]}")

        for protocol, count in protocol_counter.items():
            if protocol not in protocol_order:
                print(f"{protocol:<10}: {count}")

    else:
        print("No packets captured.")

    print(Fore.CYAN + "=" * 70)

    export_to_csv()
    generate_report()


def main():
    show_banner()

    selected_interface = select_interface()
    capture_filter = select_filter()

    if not confirm_capture(selected_interface, capture_filter):
        return

    capture_packets(selected_interface, capture_filter)


if __name__ == "__main__":
    main()
