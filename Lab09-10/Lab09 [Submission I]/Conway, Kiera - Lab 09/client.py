from __future__ import print_function

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Network Address Translation [Client]

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
SERVER_IP = '192.168.70.129'
SERVER_PORT = 1234


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
    tcp_packet = IP(dst=SERVER_IP) / TCP(dport=SERVER_PORT) / Raw(load=data)

    """ Send Packet """
    send(tcp_packet, iface="ens33")


""" ===== Main Script Starts Here ===== """

if __name__ == "__main__":
    
    packet_data = b"Hello from client"
    
    send_tcp_packet(packet_data)
    print(f"[*] TCP Packet Sent")
    
''' End of Main Script '''