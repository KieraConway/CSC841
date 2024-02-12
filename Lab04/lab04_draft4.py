from __future__ import print_function

import sys          # import Python Standard Sys Library
from scapy.all import *
import netifaces
import inspect
import subprocess
import time
import threading
from datetime import datetime
import getopt

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
debug_mode = False
def set_scan_duration():
    global scan_duration_default, debug_mode

    scan_duration = -1
    ''' Parse Command Line Input '''
    # Parse User Input
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:", ["help", "duration=", "debug"])

        for opt, arg in opts:
            if opt in ['-h', '--help']:
                usage()
                exit()

            if opt in ['-d', '--duration']:
                scan_duration = int(arg)

            elif opt in ['-h', '--help']:
                usage()
                exit()

            elif opt in ['--debug']:
                debug_mode = True

    except Exception as err:
        print(f'Invalid Input: {err}\n Restoring Default Settings ...\n\n')

    if scan_duration == -1:
        scan_duration = scan_duration_default

    # inform user
    if scan_duration > 0:
        debug_print(f"[*] Scan Duration set to {scan_duration} seconds")
    else:
        debug_print(f"[*] Scan will continue until stopped manually")

    debug_print(f"[*] Debug mode {'enabled' if debug_mode else 'disabled'}")

    return scan_duration


def find_wlan_interface():
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    interfaces = netifaces.interfaces()  # scan interfaces

    wlan_interfaces = [each for each in interfaces if
                       each.startswith('wlan')]  # find all interfaces that start with 'wlan'

    return wlan_interfaces


def select_interface(wlan_interfaces):
    'check if multiple wlan found and select target'
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    if len(wlan_interfaces) == 0:
        print("  ! Unable to locate 'wlan' interface\n    Exiting Program...")
        exit()

    elif len(wlan_interfaces) == 1:
        return wlan_interfaces[0]  # Return target

    else:
        print("\n[*] Multiple 'wlan' interfaces discovered:")
        for i, each in enumerate(wlan_interfaces, start=1):
            print(f"{i}. {each}")

        user_input = input(" | Select target interface \n> ").strip()

        if user_input.isdigit() and 1 <= int(user_input) <= len(wlan_interfaces):
            return wlan_interfaces[int(user_input) - 1]  # Return Selection as Target

        else:
            print("  ! Invalid Option - Option 1 Selected as Default.")
            return wlan_interfaces[0]  # Return Option 1 as Default target


def get_interface_info(target_interface):
    global monitor_mode, interface_channel
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

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
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    ' Check if already in monitor mode '
    if not monitor_mode:
        try:
            subprocess.call(['sudo', 'ifconfig', target_interface, 'down'])
            subprocess.call(['sudo', 'iwconfig', target_interface, 'mode', 'monitor'])
            subprocess.call(['sudo', 'ifconfig', target_interface, 'up'])

        except subprocess.CalledProcessError as err:
            print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
            exit()

        debug_print("  | Monitor Mode Enabled")
        return True


def weighted_channel_hopper(target_interface, total_duration):
    global scan_complete

    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    try:
        start_time = time.time()

        while (total_duration == 0 or time.time() - start_time < total_duration) and not scan_complete:
            for channel in range(1, 15):
                subprocess.call(['sudo', 'iwconfig', target_interface, 'channel', str(channel)])
                debug_print(f"[*] Switched to Channel {channel}")

                if channel == 1 or channel == 6 or channel == 11:
                    weight = 1.2  # Higher weight for channels 1, 6, and 11
                else:
                    weight = 1

                time.sleep(weight)

        # Set the event to signal that channel hopping is done
        scan_complete = True
        return

    except KeyboardInterrupt:
        print("[*] KeyboardInterrupt: Stopping packet sniffing.")
        scan_complete = True
        return

    except subprocess.CalledProcessError as err:
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()


def packet_sniffer(target_interface):
    global scan_complete

    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    try:
        sniff(iface=target_interface,
              prn=parse_frame,
              store=0,
              filter="type mgt subtype beacon",
              stop_filter=lambda x: scan_complete)

    except KeyboardInterrupt:
        print("[*] KeyboardInterrupt: Stopping packet sniffing.")
        scan_complete = True
        return

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

        if not essid.strip():
            essid = "[hidden]"

        print(f'{essid:<30}'
              f'{bssid:<20}'
              f'{datetime.fromtimestamp(timestamp)}'
              f'{beacon_interval:<10}'
              f'{channel}')

#
# Function:     usage()
#
# Purpose:      Displays the usage summary for the email address DFA simulation
#
def usage():
    print_line(95)
    print("Script to Capture and Parse 802.11 Beacon frames\n "
          "ver 1.0, 2024\n "
          "Usage: python 3 conway_capture.py -h -v\n\n"
          "-h  |  --help \t\t Display Usage summary \t|   Example: python 3 conway_capture.py -h\n",
          "-d  |  --duration <seconds> \t\t Set Scan Duration \t|   Example: python 3 conway_capture.py --duration 20\n",
          "    |  --debug \t Enable Debug Mode \t\t|   Example: python 3 conway_capture.py --debug\t")
    print_line(95)


#
# Function:     print_line(length)
#
# Purpose:      Prints a line of specified length using hyphens
#
# Parameters:   length - The length of the line to be printed
#
def print_line(length):
    print()
    for i in range(0, length):
        print("-", end='')  # Print Separator
    print("\n")


def debug_print(string):
    if debug_mode:
        print(string)


if __name__ == "__main__":
    '''
    Initialize
    '''
    # Determine Scan Duration
    scan_duration = set_scan_duration()

    # Select Target Adapter
    debug_print(f"[*] Selecting Target")
    wlan_interfaces = find_wlan_interface()  # Locate Adapter
    target_interface = select_interface(wlan_interfaces)  # Select Target
    debug_print(f"  * '{target_interface}' selected as target")

    # Get Interface Info
    debug_print(f"\n[*] Obtaining Interface Information")
    get_interface_info(target_interface)

    # Ensure Monitor Mode
    debug_print(f"\n[*] Enabling Monitor Mode")
    set_monitor_mode(target_interface)

    '''
    Spawn Threads
    '''
    debug_print(f"\n[*] Spawning Threads")
    # Spawn Threads
    t_hopper = threading.Thread(target=weighted_channel_hopper, args=(target_interface, scan_duration), daemon=True)
    t_sniffer = threading.Thread(target=packet_sniffer, args=(target_interface,))

    # Start Threads
    t_hopper.start()
    t_sniffer.start()


    '''
    Join Threads
    '''
    t_hopper.join()
    t_sniffer.join()
    debug_print(f"\n[*] Threads Joined Successfully")

    debug_print(f"\n[*] End of Script")
''' End of Main Script '''