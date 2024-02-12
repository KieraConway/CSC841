from __future__ import print_function

import json
import socket
import sys          # import Python Standard Sys Library
from scapy.all import *
import netifaces
import inspect
import subprocess
import time
import threading
from datetime import datetime

'''
Script Title:   Lab04 - 802.11 Parsing
Script Purpose: Capture and Parse 802.11 Beacon frames
Script Author:  Kiera Conway, Student - Dakota State University

'''

# Globals
monitor_mode = False
interface_channel = None
frequency_to_channel = {
    2.412: 1,
    2.417: 2,
    2.422: 3,
    2.427: 4,
    2.432: 5,
    2.437: 6,
    2.442: 7,
    2.447: 8,
    2.452: 9,
    2.457: 10,
    2.462: 11,
    2.467: 12,
    2.472: 13,
    2.484: 14
}

#run duration
scan_complete = False
scan_duration_default = 30

def find_wlan_interface():
    print(f"[!] starting {inspect.currentframe().f_code.co_name}")

    interfaces = netifaces.interfaces()  # scan interfaces

    wlan_interfaces = [each for each in interfaces if
                       each.startswith('wlan')]  # find all interfaces that start with 'wlan'

    return wlan_interfaces


def select_interface(wlan_interfaces):
    'check if multiple wlan found and select target'
    print(f"[!] starting {inspect.currentframe().f_code.co_name}")

    if len(wlan_interfaces) == 0:
        print("[!] Unable to locate 'wlan' interface\n    Exiting Program...")
        exit()

    elif len(wlan_interfaces) == 1:
        return wlan_interfaces[0]  # Return target

    else:
        print("[*] Multiple 'wlan' interfaces discovered:")
        for i, each in enumerate(wlan_interfaces, start=1):
            print(f"{i}. {each}")

        user_input = input("[*] Select target interface \n> ").strip()

        if user_input.isdigit() and 1 <= int(user_input) <= len(wlan_interfaces):
            return wlan_interfaces[int(user_input) - 1]  # Return Selection as Target

        else:
            print("[*] Invalid Option - first interface selected as default.")
            return wlan_interfaces[0]  # Return Option 1 as Default target

def get_interface_info(target_interface):
    global monitor_mode, interface_channel
    print(f"[!] starting {inspect.currentframe().f_code.co_name}")

    try:
        output = subprocess.check_output(['iwconfig', target_interface]).decode('utf-8')

        monitor_mode = 'Mode:Monitor' in output  # verify monitor mode is active

        # Extract channel information from frequency
        for each in output.split():
            if 'Frequency' in each:
                freq = float(each.split(':')[1])

                # Determine channel based on frequency (2.4 GHz band)
                interface_channel = frequency_to_channel.get(freq)
                return

    except subprocess.CalledProcessError as err:
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()

def set_monitor_mode(target_interface):
    global monitor_mode
    print(f"[!] starting {inspect.currentframe().f_code.co_name}")

    ' Check if already in monitor mode '
    if not monitor_mode:
        try:
            subprocess.call(['sudo', 'ifconfig', target_interface, 'down'])
            subprocess.call(['sudo', 'iwconfig', target_interface, 'mode', 'monitor'])
            subprocess.call(['sudo', 'ifconfig', target_interface, 'up'])

            print("[*] Monitor Mode Successfully Set")
            return True

        except subprocess.CalledProcessError as err:
            print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
            exit()
    else:
        print(f"[*] Monitor Mode Already Set")


def weighted_channel_hopper(target_interface, total_duration):
    global scan_complete
    try:
        start_time = time.time()

        while total_duration == 0 or time.time() - start_time < total_duration:
            for channel in range(1, 15):
                subprocess.call(['sudo', 'iwconfig', target_interface, 'channel', str(channel)])
                print(f"Switched to channel {channel}")

                if channel == 1 or channel == 6 or channel == 11:
                    weight = 1.2  # Higher weight for channels 1, 6, and 11
                else:
                    weight = 1

                time.sleep(weight)

        # Set the event to signal that channel hopping is done
        scan_complete = True

    except subprocess.CalledProcessError as err:
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()


def packet_sniffer(target_interface):
    global scan_complete

    try:
        sniff(iface=target_interface,
              prn=parse_frame,
              store=0,
              filter="type mgt subtype beacon",
              stop_filter=lambda x: scan_complete)

    except Exception as err:
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}")

def parse_frame(frame):
    # Ensure Frame is Beacon
    if frame.haslayer(Dot11Beacon):
        channel = int(ord(frame[Dot11Elt:3].info))
        essid = frame.info.decode("utf-8")
        bssid = frame.addr3
        timestamp = frame.time
        beacon_interval = frame.beacon_interval
        print(f'{essid}\t{bssid}\t{datetime.fromtimestamp(timestamp)}\t{beacon_interval}\t{channel}')


def set_scan_duration():
    global scan_duration_default


    # variable creation
    if len(sys.argv) == 2:              # check if user inputs scan limit
        try:
            scan_duration = int(sys.argv[1])
            if scan_duration < 0:
                print(f"[!] {inspect.currentframe().f_code.co_name} Error: Please enter a non-negative integer\n    Exiting Program...")
                exit()
        except ValueError as err:
            print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
            exit()
    else:
        scan_duration = scan_duration_default   #else, use default (30s)

    # inform user
    if scan_duration == 0:
        print("[*] Scan will continue until stopped manually")
    else:
        print("[*] Scan will continue for {scan_duration} seconds")





if __name__ == "__main__":

    #todo: prompt for scan duration (or in argument/set default)
    #min 15 seconds recommended
    pcap=False
    '''
    if pcap:
        capture = sniff(...)
        wrpcap("scan.pcap", capture)
    '''
    scan_duration = 20
    '''
    1) Select Target Adapter
    '''
    print(f"[*] Selecting Target")
    wlan_interfaces = find_wlan_interface()  # Locate Adapter
    target_interface = select_interface(wlan_interfaces)  # Select Target
    print(f"[*] Interface '{target_interface}' selected as target")

    '''
    2) Get Interface Info
    '''
    print(f"[*] Getting Interface Info")
    get_interface_info(target_interface)
    print(f"Mode:{monitor_mode} {type(monitor_mode)} | Channel: {interface_channel} {type(interface_channel)} ")

    '''
    3) Set in Monitor Mode
    '''
    print(f"[*] Setting Monitor Mode")
    set_monitor_mode(target_interface)

    '''
    2) Spawn Threads
    '''
    #Channel Hopper
    t_hopper = threading.Thread(target=weighted_channel_hopper, args=(target_interface, scan_duration), daemon = True)

    #capture frames
    t_sniffer = threading.Thread(target=packet_sniffer, args=(target_interface))


    t_hopper.start()
    t_sniffer.start()

    t_hopper.join()
    t_sniffer.join()



    '''
    3) capture 802.11 frames
    '''
    # subprocess.call(['sudo', 'airmon-ng', 'start', target_interface])


    '''
    4) parse frames
        ESSID
        BSSID
        Timestamp
        Beacon Interval
        Other fields of your choosing
    '''

    '''
    5) display to the screen
    '''
    #:
