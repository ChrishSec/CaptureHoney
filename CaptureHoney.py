"""

__author__ = "ChrishSec"
__copyright__ = "Copyright (C) 2024 ChrishSec"
__license__ = "GNU General Public License v3.0"
__version__ = "1.0.0"

Website: https://ChrishSec.com
GitHub: https://github.com/ChrishSec
Twitter: https://twitter.com/ChrishSec

"""

import os
import re
import sys
import json
import socket
import requests
import argparse

LOG_FILE = "capture_honey_logs/capture_honey_logs.txt"

def log_file(log_data):
    with open(LOG_FILE, "a") as file:
        file.write(log_data + "\n")

def client_info(client_socket):
    return ""

def ip_info(real_ip):
    try:
        api_url = f"http://ip-api.com/json/{real_ip}"
        response = requests.get(api_url)
        response.raise_for_status()
        ip_info_data = response.json()
        cleaned_ip_info = json.dumps(ip_info_data, indent=2)
        return cleaned_ip_info
    except requests.RequestException as e:
        print(f" Error retrieving IP information: {e}")
        return None

def html_response(client_socket, html_content):
    try:
        response = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{html_content}"
        client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f" Error sending HTML response: {e}")

def main(args):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server_socket.bind((args.ip, args.port))
        server_socket.listen(10)
    except Exception as e:
        print(f" Error setting up server socket: {e}")
        return
    
    os.system('clear')
    print(f"\n [+] Launching CaptureHoney System - 'IP: {args.ip} Port: {args.port}' - Ready for Intrusion Detection. \n\n")

    with open("custom_message/custom_message.html", "r") as html_file:
        custom_message_html = html_file.read()

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(client_info(client_socket), end='')

            data = client_socket.recv(30000)

            try:
                decoded_data = data.decode('utf-8')
            except UnicodeDecodeError:
                decoded_data = data.decode('latin-1')

            match = re.search(r'GET\s+(/\S*)\s+HTTP', decoded_data)
            path = match.group(1) if match else '/'

            if path == '/favicon.ico':
                client_socket.close()
                continue

            user_agent = decoded_data.split('User-Agent: ')[1].split('\r\n', 1)[0] if 'User-Agent: ' in decoded_data else 'Unknown User Agent'

            real_ip = client_address[0]

            ip_info_data = ip_info(real_ip)
            if ip_info_data:
                ip_info_json = json.loads(ip_info_data)
                print(" DEVELOPED BY >> ChrishSec.com\n\n")
                print("======================================\n\n\n", end='')
                print(f" Visited Path: {path}")
                print(f" IP Address: {real_ip}")
                print(f" Browser: {user_agent}")
                print(f" Country: {ip_info_json.get('country', 'N/A')}")
                print(f" City: {ip_info_json.get('city', 'N/A')}")
                print(f" Lat: {ip_info_json.get('lat', 'N/A')}")
                print(f" Lon: {ip_info_json.get('lon', 'N/A')}")
                print(f" Timezone: {ip_info_json.get('timezone', 'N/A')}")
                print(f" ISP: {ip_info_json.get('isp', 'N/A')}\n\n")
                print("======================================\n\n\n", end='')

                log_data = (
                    f"Visited Path: {path}\n"
                    f"IP Address: {real_ip}\n"
                    f"Browser: {user_agent}\n"
                    f"Country: {ip_info_json.get('country', 'N/A')}\n"
                    f"City: {ip_info_json.get('city', 'N/A')}\n"
                    f"Lat: {ip_info_json.get('lat', 'N/A')}\n"
                    f"Lon: {ip_info_json.get('lon', 'N/A')}\n"
                    f"Timezone: {ip_info_json.get('timezone', 'N/A')}\n"
                    f"ISP: {ip_info_json.get('isp', 'N/A')}\n"
                )
                log_file(log_data)

                html_response(client_socket, custom_message_html)

            client_socket.close()

    except KeyboardInterrupt:
        print("\n [+] Stopping CaptureHoney.py. Closing server socket.")
        server_socket.close()
        sys.exit(0)
    except Exception as e:
        print(f" An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CaptureHoney.py with Command-Line Arguments")
    parser.add_argument("-ip", default="0.0.0.0", help="IP address to bind to")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port number to listen on")
    args = parser.parse_args()
    main(args)
