from __future__ import print_function

from scapy.all import *
import netifaces
import inspect
import subprocess
import threading
import os

'''
Script Title:   Lab04 - 802.11 Parsing
Script Purpose: Capture and Parse 802.11 Beacon frames
Script Author:  Kiera Conway, Student - Dakota State University

'''

'''
def channel_hop():
    # scan multiple channels (create function to jump channels)
    # 1, 6, 11 are most common channels on 2.5GhZ

    # random number generator?
    channelNumber = generatorHERE
    os.system('iwconfig wlan0mnon channel %d' % (channelNumber))


def parse_frame(frame):
    # Ensure Frame is Beacon
    if frame.haslayer(Dot11Beacon):
        ssid = frame.getlayer(Dot11Elt, ID=0).info.decode("utf-8")
        ##
'''
def find_wlan_adapter():
    interfaces = netifaces.interfaces()                 # scan interfaces
    wlan_interfaces = [each for each in interfaces if
                       each.startswith('wlan')]         # find all interfaces that start with 'wlan'
    return wlan_interfaces

def select_interface(wlan_interfaces):
    'check if multiple wlan found and select target'

    if len(wlan_interfaces) == 0:
        print("[!] Unable to locate 'wlan' interface\n    Exiting Program...")
        exit()

    elif len(wlan_interfaces) == 1:
        return wlan_interfaces[0]       # Return target

    else:
        print("[*] Multiple 'wlan' interfaces discovered:")
        for i, each in enumerate(wlan_interfaces, start=1):
            print(f"{i}. {each}")

        user_input = input("[*] Select target interface \n> ").strip()

        if user_input.isdigit() and 1 <= int(user_input) <= len(wlan_interfaces):
            return wlan_interfaces[int(user_input) - 1]  # Return Selection as Target

        else:
            print("[*] Invalid Option - first interface selected as default.")
            return wlan_interfaces[0]       # Return Option 1 as Default target


def in_monitor_mode(target_interface):
    try:
        output = subprocess.check_output(['iwconfig', target_interface]).decode('utf-8')

        return 'Mode:Monitor' in output

    except subprocess.CalledProcessError:
        return False

def set_monitor_mode(target_interface):

    ' Check if already in monitor mode '
    if not in_monitor_mode(target_interface):
        try:
            subprocess.call(['sudo', 'airmon-ng', 'start', target_interface])
            print("[*] Monitor Mode Successfully Set")
            return True
        except Exception as err:
            print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()

if __name__ == "__main__":
    '''
    1) Select Target Adapter
    '''
    wlan_interfaces = find_wlan_adapter()                   # Locate Adapter
    target_interface = select_interface(wlan_interfaces)    # Select Target
    print(f"[*] Interface '{target_interface}' selected as target")


    '''
    2) Set in Monitor Mode
    '''
    set_monitor_mode(target_interface)





    '''
    2) Get Channel
    '''



    '''
    3) capture 802.11 frames
    '''

    '''
    thread = threading.Thread(target=channel_hop, name="channelHopper")
    thread.daemon = True
    thread.start()

    '''
    sniff(iface=interface, prn=parse_frame, store=0)

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
    :
