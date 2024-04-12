from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Server]

    Assignment  Assignment  Lab10 - Submission 2
    Purpose     Simulate NAT Poxy
    Due         April 05, 2024
    University  Dakota State University
    Student     Kiera Conway

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
""" ===== Script Module Importing ===== """
# Python 3rd Party Libraries
from scapy.all import *

""" ===== Defining Pseudo Constants ===== """
SERVER_IP = '192.168.172.130'
SERVER_PORT = 50000

IFACE = 'ens33'

#
# Function:     generate_message()
#
# Purpose:      Generate response message
#
# Parameters:   original_payload (str)  original payload received from client
#               protocol (str)          protocol used for communication ('TCP', 'UDP')
#
# Returns:      str - generated response message
#
def generate_message(original_payload, protocol):
    # Extract counter value from the message based on the protocol

    if protocol == 'TCP':
        counter = int(original_payload.split(': ')[1].rstrip('.'))
        return f"Hello back from Server: {counter + 1}"
    
    
    elif protocol == 'UDP':
        counter = int(original_payload.split(': ')[1])
        return f"Sweety {counter + 1}"

#
# Function:     send_packet()
#
# Purpose:      Send packet with specified parameters
#
# Parameters:
#               layer (str)     Protocol layer ('TCP' or 'UDP')
#               dst_ip (str)    Destination IP address
#               dst_port (int)  Destination port
#               data (bytes)    Payload data
#
# Returns:      None
# Returns:      None
#
def send_packet(layer, dst_ip, dst_port, data):
    packet = None

    if layer == 'TCP':
        """ Construct TCP Packet """
        packet = IP(src=SERVER_IP, dst=dst_ip) / TCP(sport=SERVER_PORT, dport=dst_port) / Raw(load=data)

    elif layer == 'UDP':
        """ Construct UDP Packet """
        packet = IP(src=SERVER_IP, dst=dst_ip) / UDP(sport=SERVER_PORT, dport=dst_port) / Raw(load=data)

    """ Send Packet """
    if packet is not None:
        send(packet, iface=IFACE, verbose=False)

        # Extract Packet Data for Logging
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[layer].sport
        dst_port = packet[layer].dport

        # Log Packet Data and Payload
        if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
            chksum = packet[layer].chksum
            payload_hex = packet[Raw].load.hex()
            payload_str = packet[Raw].load.decode('utf-8', errors='ignore')

            print_payload(src_ip, src_port, dst_ip, dst_port, chksum, payload_hex, payload_str, 'send')


#
# Function:     print_payload()
#
# Purpose:      Print packet payload details
#
# Parameters:
#               src_ip (str)-       Source IP address
#               src_port (int)-     Source port number
#               dst_ip (str)-       Destination IP address
#               dst_port (int)-     Destination port number
#               chksum (int)-       Checksum value
#               payload_hex (str)-  Payload of packet in hexadecimal format
#               payload_str (str)-  Payload of packet in decoded string format
#               msg_dir (str)-      Direction of message ('recv' for received, 'send' for sent)
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
# Function:     handle_packet()
#
# Purpose:      Process and display incoming packets
#
# Parameters:   packet - the packet received by scapy's sniffing process
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

    try:
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

                # Extract Payload Contents
                payload_bytes = pkt_wrap[Raw].load  # Payload as bytes
                payload_hex = payload_bytes.hex()  # Payload as hex
                payload_str = payload_bytes.decode('utf-8', errors='ignore')  # Payload as string
                
                # Verify Payload Contents                
                if len(payload_hex) > 0:

                    print_payload(src_ip, src_port, dst_ip, dst_port, chksum, payload_hex, payload_str, 'recv')

                    if payload_hex.strip('0') != '':
                        #
                        # Respond to message
                        #
                        packet_data = generate_message(payload_str, layer)

                        print(f"|<\n| Response to {layer} Packet ({pkt_wrap.chksum}) Sent\n|>\n")
                        send_packet(layer, src_ip, src_port, packet_data)
    except Exception as err:
        print(f"[!] Error processing packet: {err}")


""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    duration = 30  # listen duration (30s)

    '''sniff(prn=handle_packet, filter=f"(tcp and port {SERVER_PORT}) or (udp and port {SERVER_PORT})", iface=IFACE, timeout=duration)'''

    filter_rules = f"(not src net 192.0.0.0/8) and (src net 138.0.0.0/8) and (dst host {SERVER_IP})"

    # Rules Overview:
    # (not src net 192.0.0.0/8) - excludes packets where source IP falls within the "192." range
    # (src net 138.0.0.0/8) - packets from the "138." range are accepted
    # (dst host SERVER_IP) -  only packets targeted to SERVER_IP are accepted
    #


    # sniff(prn=handle_packet, filter=filter_rules, iface=IFACE, timeout=duration)
    sniff(prn=handle_packet, filter=filter_rules, iface=IFACE)

''' End of Main Script '''

