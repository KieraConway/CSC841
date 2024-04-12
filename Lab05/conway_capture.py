from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Code 2 - Dynamic Algorithm

    Assignment  Lab04 - 802.11 Parsing
    Purpose     Capture and Parse 802.11 Beacon frames
    Due         February 09, 2024
    University  Dakota State University
    Student     Kiera Conway

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""

""" ===== Script Module Importing ===== """
# Python Standard Libraries
from datetime import datetime   # date/time conversion
import getopt                   # command-line option parsing
import inspect                  # extracting function names
import subprocess               # executing shell commands
import sys                      # standard sys library
import threading                # multi-threading support
import time                     # time-related operations

# Python 3rd Party Libraries
import netifaces                # network interface information retrieval
from scapy.all import *         # packet manipulation and analysis


""" ===== Defining Script Globals ===== """
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
}                               # wifi frequency to channel mapping
interface_channel = None        # store interface channel
scan_duration_default = 30      # default scan duration (seconds)

scan_complete = Event()  # flag - scan operation is complete
monitor_mode = False            # flag - monitor mode is enabled
debug_mode = False              # flag - debug mode is enabled


#
# Function:     set_scan_duration()
#
# Purpose:      Sets scan duration based on user input or default value
#
# Parameters:   None
#
# Returns:      scan_duration - duration (seconds)
#
def set_scan_duration():

    """ Function Initialization """
    # Initialize Variables
    global scan_duration_default, debug_mode
    scan_duration = -1


    """ Parse Command Line Input """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:", ["help", "duration=", "debug"])

        for opt, arg in opts:

            # Check for 'help' Argument
            if opt in ['-h', '--help']:
                usage()
                exit()

            # Check for 'duration' Argument
            if opt in ['-d', '--duration']:
                scan_duration = int(arg)

            # Check for 'debug' Argument
            elif opt in ['--debug']:
                debug_mode = True

    except Exception as err:
        print(f'[!] Invalid Input: {err}\n  | Restoring Default Settings ...\n\n')

    """ Set Defaults """
    if scan_duration == -1:
        scan_duration = scan_duration_default           # set default if duration not specified

    """ Print Data """
    if scan_duration > 0:
        debug_print(f"[*] Scan Duration set to {scan_duration} seconds")
    else:
        debug_print(f"[*] Scan will continue until stopped manually")

    debug_print(f"[*] Debug mode {'enabled' if debug_mode else 'disabled'}")

    """ Return Set Scan Duration """
    return scan_duration

#
# Function:     find_wlan_interface()
#
# Purpose:      Locates WLAN interfaces available on system
#
# Parameters:   None
#
# Returns:      wlan_interfaces - list of WLAN interfaces found on system
#
def find_wlan_interface():
    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    # Scan Network Interfaces
    interfaces = netifaces.interfaces()

    # Filter WLAN Interfaces
    wlan_interfaces = [each for each in interfaces if
                       each.startswith('wlan')]

    # Return list of WLAN interfaces
    return wlan_interfaces


#
# Function:     select_interface(wlan_interfaces)
#
# Purpose:      Selects WLAN interface from list of available interfaces
#
# Parameters:   wlan_interfaces - list of WLAN interfaces found on system
#
# Returns:      selected_interface - The selected WLAN interface
#
def select_interface(wlan_interfaces):
    """ Function Initialization """
    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    """ Handle WLAN Interfaces """
    # No WLAN Interfaces Discovered
    if len(wlan_interfaces) == 0:
        print("  ! Unable to locate 'wlan' interface\n    Exiting Program...")
        exit()

    # One WLAN Interface Discovered
    elif len(wlan_interfaces) == 1:
        return wlan_interfaces[0]                               # return target

    # Multiple WLAN Interfaces Discovered
    else:
        print("\n[*] Multiple 'wlan' interfaces discovered:")

        # Enumerate Found Interfaces
        for i, each in enumerate(wlan_interfaces, start=1):
            print(f"{i}. {each}")

        # Prompt User for Target
        user_input = input(" | Select target \n> ").strip()

        # Verify and Return Selection
        if user_input.isdigit() and 1 <= int(user_input) <= len(wlan_interfaces):
            return wlan_interfaces[int(user_input) - 1]         # if valid, return target

        else:
            print("  ! Invalid Option - Option 1 Selected as Default.")
            return wlan_interfaces[0]                           # if not valid, return option 1 as target


#
# Function:     get_interface_info(target_interface)
#
# Purpose:      Retrieves information about target interface
#
# Parameters:   target_interface - Name of target interface
#
# Returns:      None
#
def get_interface_info(target_interface):
    """ Function Initialization """
    # Initialize Global Variables Access
    global monitor_mode, interface_channel

    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    """ Retrieve Information """
    try:
        # Execute iwconfig Command and Decode Output
        output = subprocess.check_output(['iwconfig', target_interface]).decode('utf-8')

        # Verify Monitor Mode
        monitor_mode = 'Mode:Monitor' in output

        # Extract Channel Information from Frequency
        for each in output.split():
            if 'Frequency' in each:
                freq = float(each.split(':')[1])

                # Determine Channel Based on Frequency (2.4 GHz band)
                interface_channel = frequency_to_channel.get(freq)
                return

    except subprocess.CalledProcessError as err:
        # Handle Subprocess Errors
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()


#
# Function:     set_monitor_mode(target_interface)
#
# Purpose:      Sets monitor mode for target interface
#
# Parameters:   target_interface - Name of the interface to set to monitor mode
#
# Returns:       True - monitor mode successfully enabled
#
def set_monitor_mode(target_interface):
    """ Function Initialization """
    # Initialize Global Variables Access
    global monitor_mode

    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    """ Verify and Set Monitor Mode """
    if not monitor_mode:
        try:
            # Execute Shell Commands to Set Monitor Mode
            subprocess.call(['sudo', 'ifconfig', target_interface, 'down'])
            subprocess.call(['sudo', 'iwconfig', target_interface, 'mode', 'monitor'])
            subprocess.call(['sudo', 'ifconfig', target_interface, 'up'])

        except subprocess.CalledProcessError as err:
            # Handle Subprocess Errors
            print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
            exit()

        debug_print("  | Monitor Mode Enabled")
        return True


#
# Function:     weighted_channel_hopper(target_interface, total_duration)
#
# Purpose:      Perform weighted channel hopping on target interface for specified duration
#
# Parameters:   target_interface - Name of target interface to perform channel hopping on
#               total_duration   - Total hopping duration
#
# Returns:      None
#
def weighted_channel_hopper(target_interface, total_duration):
    """ Function Initialization """
    # Initialize Global Variables Access
    global scan_complete

    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    """ Channel Hop """
    try:
        # Initialize Start Time
        start_time = time.time()

        # Continue for Duration
        while total_duration == 0 or time.time() - start_time < total_duration:

            for channel in range(1, 15):
                # Set Channel
                subprocess.call(['sudo', 'iwconfig', target_interface, 'channel', str(channel)])
                debug_print(f"\n[*] Scanning Channel {channel}")

                # Set Weights
                if channel == 1 or channel == 6 or channel == 11:
                    weight = 1.2            # higher weights for channels 1, 6, and 11
                else:
                    weight = 1

                # Sleep for Weighted Duration
                time.sleep(weight)

        # Signal Hopping is Complete
        scan_complete.set()        

        return

    except KeyboardInterrupt:
        # Handle Keyboard Interrupt
        print("[*] KeyboardInterrupt: Stopping packet sniffing.")
        scan_complete.set()
        return

    except subprocess.CalledProcessError as err:
        # Handle Subprocess Errors
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}\n    Exiting Program...")
        exit()


#
# Function:     packet_sniffer(target_interface)
#
# Purpose:      Sniff and process packets on target interface
#
# Parameters:   target_interface - Target interface to sniff
#
# Returns:      None
#
def packet_sniffer(target_interface):
    """ Function Initialization """
    # Initialize Global Variables Access
    global scan_complete

    # Print Debug Message
    debug_print(f"  | starting {inspect.currentframe().f_code.co_name}")

    """ Sniff and Filter Packets """
    try:
        while scan_complete.is_set() == False:
        
              sniff(iface=target_interface,
                    prn=parse_frame,
                    store=0,
                    filter="type mgt subtype beacon")
    except KeyboardInterrupt:
        # Handle Keyboard Interrupt
        print("[*] KeyboardInterrupt: Stopping packet sniffing.")
        scan_complete.set()
        return

    except Exception as err:
        # Handle other exceptions
        print(f"[!] {inspect.currentframe().f_code.co_name} Error: {err}")

#
# Function:     parse_frame(frame)
#
# Purpose:      Parse and display frame information
#
# Parameters:   frame - The 802.11 frame to parse
#
# Returns:      None
#
def parse_frame(frame):

    # Ensure Frame is Beacon
    if frame.haslayer(Dot11Beacon):

        # Extract Information from Frame
        channel = int(ord(frame[Dot11Elt:3].info))
        essid = frame.info.decode("utf-8")
        bssid = frame.addr3
        timestamp = frame.time
        beacon_interval = frame.beacon_interval

        # Set "[hidden]" if ESSID is Empty
        if ord(essid[0:1])==0:
            essid = "[hidden]"

        # Display Information
        print(f'{essid:<30}'
              f'{bssid:<20}'
              f'{datetime.fromtimestamp(timestamp)}'
              f'{beacon_interval:<10}'
              f'{channel}')

#
# Function:     usage()
#
# Purpose:      Displays usage summary
#
def usage():
   print_line(110)
   print("Script to Capture and Parse 802.11 Beacon frames\n "
         "ver 1.0, 2024\n "
         "Usage: python 3 conway_capture.py -h -v\n\n " 
         "-h ,  --help\t\t|  Display Usage summary \t|   Example: python 3 conway_capture.py -h\n",
         "-d ,  --duration <int>\t|  Set Scan Duration (seconds) \t|   Example: python 3 conway_capture.py --duration 20\n",
         "   ,  --debug\t\t|  Enable Debug Mode \t\t|   Example: python 3 conway_capture.py --debug\t")
   print_line(110)


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


# Function:     debug_print(string)
#
# Purpose:      Print string if debug_mode is enabled
#
# Parameters:   string - The string to print
#
# Returns:      None
#
def debug_print(string):
    if debug_mode:
        print(string)


""" ===== Main Script Starts Here ===== """
if __name__ == "__main__":
    '''
    Initialize Program
    '''
    # Determine Scan Duration
    scan_duration = set_scan_duration()

    # Select Target Adapter
    debug_print(f"[*] Selecting Target")
    wlan_interfaces = find_wlan_interface()                 # Locate Adapter
    target_interface = select_interface(wlan_interfaces)    # Select Target
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
    debug_print(f"\n[*] Threads Joining...")
    t_hopper.join()
    t_sniffer.join()


    debug_print(f"\n[*] Threads Joined Successfully")


    debug_print(f"\n[*] Script End")
''' End of Main Script '''

