# Lab 04  - 802.11 Parsing

	
 	## Lab 04 Files:

		conway_capture.py:		python script used to capture and parse 802.11 beacon frames
		lab04-screenshot.png:	screenshot of successful script execution
		README.md

	## Requirements:
		- Python 3.x
			> sudo apt-get install python3 <br>
			
		- scapy library 
			> sudo apt-get install python3-scapy
			or
			> sudo pip install scapy
			
		- Administrator/root privileges (for interface manipulation)
		
		*note: installation instructions assume Linux-based systems*
	
	## Usage:
		
		> python3 conway_capture.py [-h] [-d DURATION] [--debug]

				Command					Description				  Default		      Example
			---------------------------------------------------------------------------------------------------------
			 -h, --help				Display usage summary			-		python3 conway_capture.py -h
			
			 -d <int>,				Set scan duration (seconds)		30		python3 conway_capture.py --duration 20
			 --duration <int>
			
			 --debug				Enable debug mode			   False	python3 conway_capture.py --debug

	
	
	## Contributor(s):
		
		Kiera Conway
		Student - DSU
		CSC 841 - Cyber Operations II