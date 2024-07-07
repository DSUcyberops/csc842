# *****
# Walt
# csc842 
# 06 Jul 24
# Simple network scanner that check for conencted devices to my network.
# without having to login to my router
# *****
import scapy.all as scapy
import subprocess
import sys
import importlib.util

# Function to check and install missing packages
def install_missing_packages(package_names):
    for package in package_names:
        if importlib.util.find_spec(package) is None:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Packages to check and install
required_packages = ["scapy"]
install_missing_packages(required_packages)

# Define a list of common ports to scan
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995]

def network_scan(ip_ranges):
    devices = []

    for ip_range in ip_ranges:
        # Create an ARP request packet
        arp_request = scapy.ARP(pdst=ip_range)
        # Create an Ethernet frame to encapsulate the ARP request
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and capture the response
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        for sent, received in answered_list:
            # Perform ICMP Ping to fingerprint the OS
            icmp_ping = scapy.IP(dst=received.psrc) / scapy.ICMP()
            response = scapy.sr1(icmp_ping, timeout=1, verbose=False)

            ttl = response.ttl if response else None  # Extract TTL from ICMP response

            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'ttl': ttl,
            }
            devices.append(device_info)
            print(f"Scanned: {received.psrc} - Response: {response}")

    return devices

def os_fingerprint(mac_address, ttl):
    # Check if the MAC address belongs to Android or iOS devices based on OUI
    oui = mac_address[:8].upper()  # First 3 bytes of MAC address

    if ttl is None:
        return "Unknown", []

    # Fingerprinting based on TTL
    if ttl == 64:
        if oui.startswith("00:1A:11"):  # Apple IOS OUI
            return "iOS (Apple)", []
        elif oui.startswith("40:4E:36") or oui.startswith("FC:C2:DE"):  # Android OUI
            return "Android", []
        else:
            return "Linux", []

    elif ttl == 128:
        return "Windows", []

    elif ttl == 255:
        return "Cisco IOS", []

    # Guessing the OS based on common ports (if TTL doesn't match known values)
    guessed_os, open_ports = guess_os_from_ports(mac_address)
    return guessed_os, open_ports

def guess_os_from_ports(mac_address):
    # Define common ports for OS fingerprinting
    common_ports_by_os = {
        "Windows": [135, 139, 445],
        "Linux": [22, 80, 443],
        "iOS (Apple)": [62078, 62079],
        "Android": [5555, 8080],
        "Cisco IOS": [23]
    }

    # Extract OUI for guess
    oui = mac_address[:8].upper()  # First 3 bytes of MAC address

    # Guess OS based on OUI and common ports
    for os_type, ports in common_ports_by_os.items():
        if oui.startswith("00:1A:11") and os_type == "iOS (Apple)":
            return os_type, ports
        elif oui.startswith("40:4E:36") or oui.startswith("FC:C2:DE") and os_type == "Android":
            return os_type, ports

    # Default guess if no match found
    return "Unknown (Guessed)", []

def port_scan(ip_address, ports):
    open_ports = []

    for port in ports:
        # Craft TCP SYN packet
        tcp_syn_packet = scapy.IP(dst=ip_address) / scapy.TCP(dport=port, flags="S")

        # Send packet and capture response
        response = scapy.sr1(tcp_syn_packet, timeout=1, verbose=False)

        # Check if port is open (SYN-ACK received)
        if response and response.haslayer(scapy.TCP):
            if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                open_ports.append(port)

    return open_ports

if __name__ == "__main__":
    ip_ranges = ["192.168.100.1/24"]  # Adjusted to scan 192.168.100.1/24 based on my router
    devices = network_scan(ip_ranges)
    print("Available devices in the network:")
    print("IP Address\t\tMAC Address\t\tTTL\tOS\t\tOpen Ports")
    print("---------------------------------------------------------------")
    for device in devices:
        os_type, guessed_ports = os_fingerprint(device['mac'], device['ttl'])
        if not guessed_ports:  # Perform port scanning if no guessed ports available
            guessed_ports = port_scan(device['ip'], common_ports)  # Scan common ports
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['ttl']}\t{os_type}\t{guessed_ports}")
