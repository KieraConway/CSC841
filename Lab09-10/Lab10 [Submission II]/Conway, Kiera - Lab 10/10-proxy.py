from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Proxy]

    Assignment  Assignment  Lab10 - Submission 2
    Purpose     Simulate NAT Poxy
    Due         April 05, 2024
    University  Dakota State University
    Student     Kiera Conway

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
""" ===== Script Module Importing ===== """
# Python 3rd Party Libraries
from scapy.all import *
import subprocess
import sqlite3
import time

""" ===== Defining Pseudo Constants ===== """
CLIENT_IP = '192.168.172.128'
SERVER_IP = '192.168.172.130'
PROXY_IP = '192.168.172.129'
MIN_PORT = 0
MAX_PORT = 0
IFACE = 'ens33'

IGNORED_IPS = [
    '192.168.172.1'  # SSDP
]

REGISTERED_IPS = [
    CLIENT_IP,
    SERVER_IP,
    PROXY_IP
]


# proxy


#
# Function:     generate_mapping()
#
# Purpose:      Generate new mapping with a unique IP and port
#
# Parameters:   None
#
# Returns:
#               trans_ip (str)      unique IP address for translation
#               trans_port (int)    random port number for translation
#
def generate_mapping():
    global MIN_PORT
    global MAX_PORT

    trans_ip = f'138.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}'
    trans_port = random.randint(MIN_PORT, MAX_PORT)
    return trans_ip, trans_port


#
# Function:     add_mapping_entry()
#
# Purpose:      Inserts mapping entry into conn_mappings database
#
# Parameters:
#               orig_ip (str)       Original IP address
#               trans_ip (str)      Translated IP address
#               orig_port (int)     Original port number
#               trans_port (int)    Translated port number
#               protocol (str)      Protocol type (e.g., TCP, UDP)
#               dst_ip (str)        Destination IP address
#               dst_port (int)      Destination port number
#               checksum (int)      Checksum value
#
# Returns:      None
#

def add_mapping_entry(orig_ip, trans_ip, orig_port, trans_port, protocol, dst_ip, dst_port, checksum):
    # Calculate TCP checksum using Scapy
    tcp_checksum = TCP().chksum

    timestamp = time.time()  # TODO: Get current timestamp or use from packet

    cursor.execute('''INSERT INTO conn_mappings (orig_ip, trans_ip, orig_port, trans_port, protocol, dst_ip, dst_port, checksum, timestamp)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (orig_ip, trans_ip, orig_port, trans_port, protocol, dst_ip, dst_port, tcp_checksum, timestamp))
    conn.commit()


#
# Function:     search_database()
#
# Purpose:      Searches conn_mappings database for entries matching specified criteria
#
# Parameters:   Sets parameter(s) to search for, includes all entries if unspecified
#               orig_ip (str/None)      Original IP address
#               trans_ip (str/None)     Translated IP address
#               orig_port (int/None)    Original port number
#               trans_port (int/None)   Translated port number
#               protocol (str/None)     Protocol type (e.g., TCP, UDP)
#               dst_ip (str/None)       Destination IP address
#               dst_port (int/None)     Destination port number
#               checksum (int/None)     Checksum value
#
# Returns:      List of tuples- Row(s) that match search criteria
#               None-           no match(es) found
#
def search_database(orig_ip=None, trans_ip=None, orig_port=None, trans_port=None, protocol=None, dst_ip=None,
                    dst_port=None, checksum=None):
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM conn_mappings WHERE
                      (orig_ip=? OR ? IS NULL) AND
                      (trans_ip=? OR ? IS NULL) AND
                      (orig_port=? OR ? IS NULL) AND
                      (trans_port=? OR ? IS NULL) AND
                      (protocol=? OR ? IS NULL) AND
                      (dst_ip=? OR ? IS NULL) AND
                      (dst_port=? OR ? IS NULL) AND
                      (checksum=? OR ? IS NULL)''',
                   (orig_ip, orig_ip, trans_ip, trans_ip, orig_port, orig_port,
                    trans_port, trans_port, protocol, protocol, dst_ip, dst_ip, dst_port, dst_port, checksum, checksum))
    rows = cursor.fetchall()

    return rows  # returns None if no match is found


#
# Function:     remove_mapping_entry()
#
# Purpose:      Removes entry from conn_mappings database
#
# Parameters:
#               orig_ip (str)       Original IP address
#               trans_ip (str)      Translated IP address
#               orig_port (int)     Original port number
#               trans_port (int)    Translated port number
#               protocol (str)      Protocol type (e.g., TCP, UDP)
#               dst_ip (str)        Destination IP address
#               dst_port (int)      Destination port number
#               checksum (int)      Checksum value
#
# Returns:      None
#

def remove_mapping_entry(orig_ip, orig_port, trans_ip, trans_port, protocol, dst_ip, dst_port, checksum):
    # cursor = conn.cursor()

    cursor.execute('''DELETE FROM conn_mappings WHERE
                      orig_ip=? AND trans_ip=? AND orig_port=? AND trans_port=? AND protocol=? AND dst_ip=? AND dst_port=? AND checksum=?''',
                   (orig_ip, trans_ip, orig_port, trans_port, protocol, dst_ip, dst_port, checksum))
    conn.commit()


#
# Function:     print_payload()
#
# Purpose:      Prints packet payload details
#
# Parameters:
#               src_ip (str)        Source IP address
#               src_port (int)      Source port number
#               dst_ip (str)        Destination IP address
#               dst_port (int)      Destination port number
#               chksum (int)        Checksum value
#               payload_hex (str)   Payload of packet in hexadecimal format
#               payload_str (str)   Payload of packet in decoded string format
#               msg_dir (str)       Direction of message ('recv' for received, 'send' for sent)
#
# Returns:      None
#
def print_payload(src_ip, src_port, dst_ip, dst_port, chksum, payload_hex, payload_str, msg_dir):
    # Print Payload Contents
    try:
        if msg_dir == 'recv':
            print(f"\n\n[<] Packet Received")
        elif msg_dir == 'send':
            print(f"[>] Packet Sent")
        else:
            return

        print(f"    src: {src_ip}:{src_port}")
        print(f"    dst: {dst_ip}:{dst_port}")
        print(f"    chksum: {chksum}")
        print(f"    len: {len(payload_hex)}")
        print(f"    payload (hex): {payload_hex}")
        print(f"    payload (decoded): {payload_str}\n")

    except UnicodeDecodeError:
        print(f"    payload (invalid): Binary or Non-ASCII data")


#
# Function:     send_packet()
#
# Purpose:      Send packet with specified parameters
#
# Parameters:
#               layer (str)     Protocol layer ('TCP' or 'UDP')
#               src_ip (str)    Source IP address
#               src_port (int)  Source port
#               dst_ip (str)    Destination IP address
#               dst_port (int)  Destination port
#               chksum (int)    Checksum value
#               data (bytes)    Payload data
#
# Returns:      None
#
def send_packet(layer, src_ip, src_port, dst_ip, dst_port, chksum, data):
    packet = None

    if layer == 'TCP':
        """ Construct TCP Packet """
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, chksum=chksum) / Raw(load=data)

    elif layer == 'UDP':
        """ Construct UDP Packet """
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=data)

    """ Send Packet """
    if packet is not None:
        send(packet, iface=IFACE)

        """ Extract Packet Data """
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[layer].sport
        dst_port = packet[layer].dport

        """ Parse and Display Message """
        if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
            chksum = packet[layer].chksum
            payload_hex = packet[Raw].load.hex()
            payload_str = packet[Raw].load.decode('utf-8', errors='ignore')

            print_payload(src_ip, src_port, dst_ip, dst_port, chksum, payload_hex, payload_str, 'send')


#
# Function:     handle_packet()
#
# Purpose:      Process and display incoming packets
#
# Parameters:   packet      the packet received by scapy's sniffing process
#
# Returns:      None
#
def handle_packet(packet):
    #
    # Receive Message
    #
    """ Verify IP Layer """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip == dst_ip or src_ip in IGNORED_IPS or (src_ip.startswith('138.') and dst_ip.startswith('192.')):
            return
        # Ignore if:
        # src_ip == dst_ip:                 ignores if source IP and destination IP are the same
        # src_ip in IGNORED_IPS:            ignores some background traffic on network
        # (src_ip.startswith('138.') and/
        # dst_ip.startswith('192.'))        ignores already processed packets


        """ Set Protocol Layer """
        if packet.haslayer(TCP):
            layer = 'TCP'
            pkt_wrap = packet[TCP]
        elif packet.haslayer(UDP):
            layer = 'UDP'
            pkt_wrap = packet[UDP]
        else:
            return

        src_port = pkt_wrap.sport
        dst_port = pkt_wrap.dport

        #
        # Parse and Display Message
        #
        # Verify Payload Exists
        if pkt_wrap.payload:

            # Extract and Convert Payload and checksum
            chksum = pkt_wrap.chksum
            payload_hex = pkt_wrap[Raw].load.hex()  # Payload as hex

            try:
                # Verify Payload Contents
                if len(payload_hex) > 0:

                    # Print Payload Contents
                    payload_bytes = pkt_wrap[Raw].load  # Payload as bytes
                    payload_str = str(payload_bytes, 'utf-8')  # Payload as string
                    print_payload(src_ip, src_port, dst_ip, dst_port, chksum, payload_hex, payload_str, 'recv')

                    #
                    # Verify Mapping
                    #

                    if src_ip.startswith('192.') and dst_ip.startswith('192.'):  # If client to server (local to external)
                        # Note: these values are for simulation purposes, in real world the client IPs would be internal and the server IP would be external and both could be recognized as such

                        # Check if source has already created a translated IP/port to communicate with the server
                        mapping = search_database(orig_ip=src_ip, orig_port=src_port, protocol=layer, dst_ip=dst_ip,
                                                  dst_port=dst_port)

                        if mapping:  # If communication mapping already exists

                            print(f"[*] Existing communication mapping located")
                            trans_ip = mapping[0][1]  # extract translated ip
                            trans_port = mapping[0][3]  # extract translated port

                        else:  # If communication mapping does not exist
                            # Generate new translated IP and port
                            print(f"[*] Communication mapping does not exit, Generating...")
                            trans_ip, trans_port = generate_mapping()

                            # Add new mapping to the database
                            add_mapping_entry(orig_ip=src_ip, trans_ip=trans_ip, orig_port=src_port, trans_port=trans_port,
                                              protocol=layer, dst_ip=dst_ip, dst_port=dst_port, checksum=chksum)

                        # Update packet
                        packet[IP].src = trans_ip
                        pkt_wrap.sport = trans_port
                        print(f"|   Packet source updated")
                        print(f"|   from {src_ip}:{src_port} to {trans_ip}:{trans_port}")

                        # Forward modified packet
                        send_packet(layer, packet[IP].src, pkt_wrap.sport, dst_ip, dst_port, chksum, payload_str)
                        print(f"|>>\n| {layer} Packet ({pkt_wrap.chksum}) Forwarded to {dst_ip}\n|>>\n")
                        print_payload(packet[IP].src, pkt_wrap.sport, dst_ip, dst_port, chksum, payload_hex,
                                      payload_str, 'send')


                    elif src_ip.startswith('192.') and dst_ip.startswith('138.'):  # If server to client (external to local)
                        # Note: these values are for simulation purposes, in real world both IPs would be external and could be recognized as such

                        # Check for original IP/port to revert translations
                        mapping = search_database(trans_ip=dst_ip, trans_port=dst_port, dst_ip=src_ip, dst_port=src_port)

                        if mapping:  # If Packet mapping already exists
                            print(f"[*] Original IP/Port location, reverting translations")
                            reverted_dst_ip = mapping[0][0]  # extract original ip
                            reverted_dst_port = mapping[0][2]  # extract original port

                            # Update packet
                            packet[IP].dst = reverted_dst_ip
                            pkt_wrap.dport = reverted_dst_port
                            print(f"|   Packet destination updated")
                            print(f"|   from {dst_ip}:{dst_port} to {reverted_dst_ip}:{reverted_dst_port}")

                            # Forward modified packet
                            send_packet(layer, packet[IP].src, pkt_wrap.sport, reverted_dst_ip, reverted_dst_port, chksum, payload_str)
                            print(f"|>>\n| {layer} Packet ({pkt_wrap.chksum}) Forwarded to {reverted_dst_ip}\n|>>\n")
                            print_payload(packet[IP].src, pkt_wrap.sport, reverted_dst_ip, reverted_dst_port, chksum,
                                          payload_hex, payload_str, 'send')
            except Exception as e:
                print(f"[!] Error handling packet: {e}")



""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    """ Create State Table to Manage Connections """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # define mapping table
    cursor.execute('''CREATE TABLE IF NOT EXISTS conn_mappings
                    (orig_ip TEXT, trans_ip TEXT, orig_port INT,
                    trans_port INT, protocol TEXT, dst_ip TEXT, dst_port INT, checksum INT,
                    timestamp REAL)''')
    conn.commit()


    """ Determine Valid Port Range """
    # Execute sysctl command to get ip_local_port_range values
    ip_range = subprocess.run(['sysctl', 'net.ipv4.ip_local_port_range'], capture_output=True, text=True)

    # Extract the port range from stdout
    MIN_PORT, MAX_PORT = map(int, ip_range.stdout.split('=')[1].strip().split('\t'))

    """ Sniff and Filter TCP Packets """
    sniff(prn=handle_packet, iface="ens33")

''' End of Main Script '''
