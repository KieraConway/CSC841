# Lab 10 - Network Address Translation 

Lab 10 Files:

	10-client.py: 		simulates client-side of network communication

	10-server.py: 		simulates server-side of network communication simulation

	10-proxy.py:		simulates proxy server to mediate communication between client and servers

	csc841_lab10.mp4: 	video demonstration of network communication simulation


## Additional Notes

   - All python scripts require Python 3, scapy
      > sudo apt-get install python3 <br>
      > pip install scapy <br>
      - installation instructions assume Linux-based systems
		
   - scripts can be executed using the format `python3 programName`. 
      > python3 10-client.py

   - To ensure the server can accept connections from 138.0.0.0/8 networks, it may be necessary to configure the firewall settings (please only do so with caution). The following commands outline how to configure UFW on Ubuntu:
		1. Enable UFW:
			> sudo ufw enable
		2. Allow TCP Connections from 138.x.x.x to SERVER_IP on SERVER_PORT:
			> sudo ufw allow from 138.0.0.0/8 to SERVER_IP port SERVER_PORT proto tcp
		3. Allow UDP Connections from 138.x.x.x to SERVER_IP on SERVER_PORT:
			> sudo ufw allow from 138.0.0.0/8 to SERVER_IP port SERVER_PORT proto udp
		4. sudo ufw reload
		
		*replace SERVER_IP and SERVER_PORT with the IP address and port number used by the server application*		
	
	- Modify constants  SERVER/CLIENT_IP, SERVER/CLIENT, duration, interval, and IFACE as needed.

## Overview of Functions

10-client.py
	send_packet()			sends packet with specified parameters
	find_available_port()	finds available port within local port range
	listen_for_response()	listens for response from proxy for specified duration
	generate_message()		generates message based on specified protocol (TCP, UDP)
	message_manager()		manages generation and sending of messages
	
	Main Script Execution:

		- Initializes the client's listening port using find_available_port().
		- Starts a thread for listening to responses using listen_for_response(duration).
		- Manages the generation and sending of messages using message_manager(duration, interval).
		- Closes the socket and joins threads before exiting the program.


10-proxy.py

	generate_mapping()		generates new mapping with a unique IP and port
	add_mapping_entry()		inserts mapping entry into the conn_mappings database
	search_database() 		searches conn_mappings database for entries matches
	remove_mapping_entry()	removes entry from conn_mappings database
	print_payload()			prints packet payload details
	send_packet()			sends packet with specified parameters
	handle_packet()			processes and displays incoming packets
	
	Main Script Execution:

		- Initializes necessary variables and modules
		- Creates SQLite database to manage connection mappings
		- Sniffs and filters TCP and UDP packets using Scapy
		- Incoming packets are managed using handle_packet() to:
			- receive, parse, and prints payload details using print_payload()
			- manage connection mappings (generate new mappings/ find previous mappings) 
			- forward packets


10-server.py
	generate_message()	generates response message
	send_packet()		sends packet with specified parameters
	print_payload()		prints packet payload details
	handle_packet()		processes and displays incoming packets

	Main Script Execution:

		- Initializes server's listening port to 50000
		- Filters incoming packets based on source and destination IPs.
			- excludes packets where source IP falls within the "192." range
			- packets from the "138." range are accepted
			- only packets targeted to SERVER_IP are accepted

		- Incoming packets are managed using handle_packet() to:
			- receive, parse, and prints payload details using print_payload()
			- generate response messages using generate_message().
			- send response packets using send_packet().
			
			
			
## Editor Note:
The current functionality of the script is not at 100%. However, I plan to continue working on this project and have plans to include:

	- More control over output formatting and verbosity
	- Customizable duration for listening to incoming packets
	- Implementation of a timeout feature for packet processing
	- Enhanced logging and error handling mechanisms.
	- Support for additional protocols and packet types
	
Please note that these features are planned for future iterations and are not yet implemented in the current version of the script.

Thank you!

Kiera Conway