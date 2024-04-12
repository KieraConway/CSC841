from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Client]

    Assignment  Assignment  Lab10 - Submission 2
    Purpose     Simulate NAT Poxy
    Due         April 05, 2024
    University  Dakota State University
    Student     Kiera Conway

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
""" ===== Script Module Importing ===== """
# Python 3rd Party Libraries
from scapy.all import *
import socket
import random
import time

""" ===== Defining Pseudo Constants ===== """
SERVER_IP = '192.168.172.130'
SERVER_PORT = 50000

CLIENT_IP = '192.168.172.128'
CLIENT_PORT = 0

MIN_PORT = 0
MAX_PORT = 0

IFACE = 'ens33'

""" ===== Defining global ===== """
counter = 0


#
# Function:     send_packet()
#
# Purpose:      Send packet with specified parameters
#
# Parameters:
#               protocol (str)     Protocol layer ('TCP' or 'UDP')
#               data (bytes)    Payload data
#
# Returns:      None
#
def send_packet(protocol, data):
    packet = None

    if protocol == 'TCP':
        """ Construct Packet """
        packet = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT) / Raw(load=data)
    '''
    elif protocol == 'UDP':
        """ Construct UDP Packet """
        packet = IP(src=CLIENT_IP, dst=SERVER_IP) / UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / Raw(load=data)
    '''
    """ Send Packet """
    if packet is not None:
        send(packet, iface=IFACE)


#
# Function:     find_available_port()
#
# Purpose:      Finds available port within local port range
#
# Parameters:   None
#
# Returns:      port number and socket tuple
#
def find_available_port():
    global MIN_PORT
    global MAX_PORT

    # Execute sysctl command to get ip_local_port_range values
    ip_range = subprocess.run(['sysctl', 'net.ipv4.ip_local_port_range'], capture_output=True, text=True)

    # Extract the port range from stdout
    MIN_PORT, MAX_PORT = map(int, ip_range.stdout.split('=')[1].strip().split('\t'))

    while True:
        port = random.randint(MIN_PORT, MAX_PORT)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((CLIENT_IP, port))
                return port, s
            except OSError:
                continue


#
# Function:     listen_for_response()
#
# Purpose:      Listen for response from proxy for specified duration
#
# Parameters:   duration (int)      listen duration (seconds)
#
# Returns:      None
#
def listen_for_response(duration):

    response = sniff(filter=f"dst {CLIENT_IP}", iface=IFACE, timeout=duration)
    if response:
        print("[*] Received response from proxy:", response[0].load.decode('utf-8'))


#
# Function:     generate_message()
#
# Purpose:      Generate message based on specified protocol (TCP, UDP)
#
# Parameters:   protocol (str)          protocol used for communication ('TCP', 'UDP')
#
# Returns:      str - generated  message
#
def generate_message(protocol):
    global counter
    counter += 10
    if protocol == 'TCP':
        return f"Hello from Client: {counter}"

    if protocol == 'UDP':
        return f"Hello {counter}"



# Function:     message_manager()
#
# Purpose:      Manage generation and sending of messages
#
# Parameters:   duration (float)    runtime duration
#               interval (float)    interval between sending messages
#
# Returns:      None
#
def message_manager(duration, interval):
    start_time = time.time()

    while time.time() - start_time < duration:
        random_value = random.randint(0, 99)
        protocol = 'TCP' if random_value % 2 == 0 else 'UDP'

        packet_data = generate_message(protocol)

        send_packet(protocol, packet_data)

        print(f"[*] {protocol} Packet ({counter}) Sent")
        time.sleep(interval)


""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    duration = 30  # send message duration (30s)
    interval = 3  # send message interval (3s)

    CLIENT_PORT, socket = find_available_port()
    print(f"[*] Client listening on {CLIENT_PORT}...")

    # Start thread  for listening
    listen_thread = Thread(target=listen_for_response, args=(duration,))
    listen_thread.start()

    message_manager(duration, interval)

    # Close socket and Join threads
    socket.close()
    listen_thread.join()
    print("[*] All threads joined, program exiting.")

''' End of Main Script '''
