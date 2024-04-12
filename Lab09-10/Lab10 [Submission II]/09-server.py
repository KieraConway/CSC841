from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Server]

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
CLIENT_PORT = 9876


#
# Function:     send_tcp_packet(data)
#
# Purpose:      Construct and send TCP packet
#
# Parameters:   data - payload data to be sent in TCP packet
#
# Returns:      None
#
def send_tcp_packet(data):
    """ Construct Packet """
    tcp_packet = IP(dst=CLIENT_IP) / TCP(dport=CLIENT_PORT) / Raw(load=data)

    """ Send Packet """
    send(tcp_packet, iface="ens33")


""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    
    packet_data = b"Hello from server"
    
    send_tcp_packet(packet_data)
    print(f"[*] TCP Packet Sent")
    
''' End of Main Script '''