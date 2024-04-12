from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Proxy]

    Assignment  Lab09 - Submission 1
    Purpose     Establish Environment and TCP Communication
    Due         March 09, 2024
    University  Dakota State University
    Student     Kiera Conway

    *submission 2 will contain full implementation of NAT proxy*


"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
""" ===== Script Module Importing ===== """
# Python 3rd Party Libraries
from scapy.all import *


""" ===== Defining Pseudo Constants ===== """
CLIENT_IP = '192.168.70.130'
SERVER_IP = '192.168.70.129'


#
# Function:     handle_packet(packet)
#
# Purpose:      Process and display incoming TCP packets
#
# Parameters:   packet - the packet received by scapy's sniffing process
#
# Returns:      None
#
def handle_packet(packet):
    
    """ Verify IP/TCP Layers """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        
        # Extract Relevant Data
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        

        # Verify Payload Exists
        if packet[TCP].payload:
        
            # Extract and Convert Payload
            payload_hex = packet[TCP].payload.load.hex()
            
            # Verify Payload Contents
            if len(payload_hex) > 0:
                
                # Print Payload Contents
                try:
                    print(f"[*] Packet received from {'Client' if src_ip == '192.168.70.130' else 'Server'}")
                    print(f"    src: {src_ip}:{src_port}")
                    print(f"    dst: {dst_ip}:{dst_port}")
                    print(f"    len: {len(payload_hex)}")
                    print(f"    payload (hex): {payload_hex}")
                    
                    payload_str = bytes.fromhex(payload_hex).decode('utf-8')
                    print(f"    payload (decoded): {payload_str}\n\n")
                    
                except UnicodeDecodeError:
                    print(f"    payload (invalid): Binary or Non-ASCII data")


""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    
    """ Sniff and Filter TCP Packets """
    sniff(filter="tcp", prn=handle_packet, iface="ens33")


''' End of Main Script '''
