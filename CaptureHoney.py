#!/usr/bin/python3

"""

__author__ = "ChrishSec"
__copyright__ = "Copyright (C) 2024 ChrishSec"
__license__ = "GNU General Public License v3.0"
__version__ = "2.0.0"

Website: https://ChrishSec.com
GitHub: https://github.com/ChrishSec
Twitter: https://twitter.com/ChrishSec

"""

import os
import re
import sys
import pytz
import json
import socket
import requests
import argparse
import threading
from bs4 import BeautifulSoup
from datetime import datetime

LOG_FILE = "capture_honey_logs/capture_honey_logs.txt"
CUSTOM_MESSAGE_HTML_FILE = "custom_message/custom_message.html"

with open(CUSTOM_MESSAGE_HTML_FILE, "r") as html_file:
    custom_message_html = html_file.read()

def log_file(log_data):
    with open(LOG_FILE, "a") as file:
        file.write(log_data + "\n")

def client_info(client_socket):
    return ""

def get_current_time(country_code):
    try:
        timezone_str = pytz.country_timezones[country_code][0]
    except (KeyError, IndexError):
        print(" [!] Error: Unknown country code specified...")
        sys.exit(1)

    try:
        timezone = pytz.timezone(timezone_str)
        current_time = datetime.now(timezone)
        return current_time.strftime("%b %d, %Y - %I:%M:%S %p")
    except pytz.UnknownTimeZoneError:
        print(" [!] Error: Unknown timezone specified...")
        sys.exit(1)

def handle_client(client_socket):
    try:
        connection_time = get_current_time(args.timezone)

        data = client_socket.recv(30000)

        try:
            decoded_data = data.decode('utf-8')
        except UnicodeDecodeError:
            decoded_data = data.decode('latin-1')

        match = re.search(r'GET\s+(/\S*)\s+HTTP', decoded_data)
        path = match.group(1) if match else '/'

        if path == '/favicon.ico':
            client_socket.close()
            return

        user_agent = decoded_data.split('User-Agent: ')[1].split('\r\n', 1)[0] if 'User-Agent: ' in decoded_data else 'Unknown User Agent'
        real_ip = client_socket.getpeername()[0]

        ip_info_data = ip_info(real_ip)
        if ip_info_data:
            ip_info_json = json.loads(ip_info_data)
            print(f" DEVELOPED BY >> ChrishSec.com\n\n")
            print(f"======================================\n\n\n", end='')               
            print(f" Connection Time: {connection_time}") 
            print(f" Visited Path: {path}")
            print(f" IP Address: {real_ip}")
            print(f" Browser: {user_agent}")
            print(f" Country: {ip_info_json.get('country', 'N/A')}")
            print(f" City: {ip_info_json.get('city', 'N/A')}")
            print(f" Lat: {ip_info_json.get('lat', 'N/A')}")
            print(f" Lon: {ip_info_json.get('lon', 'N/A')}")
            print(f" Timezone: {ip_info_json.get('timezone', 'N/A')}")
            print(f" ISP: {ip_info_json.get('isp', 'N/A')}")
            print("\n\n======================================\n\n\n", end='')

            log_data = (
                f" DEVELOPED BY >> ChrishSec.com\n\n\n"
                f"======================================\n\n\n"
                f" Connection Time: {connection_time}\n"
                f" Visited Path: {path}\n"
                f" IP Address: {real_ip}\n"
                f" Browser: {user_agent}\n"
                f" Country: {ip_info_json.get('country', 'N/A')}\n"
                f" City: {ip_info_json.get('city', 'N/A')}\n"
                f" Lat: {ip_info_json.get('lat', 'N/A')}\n"
                f" Lon: {ip_info_json.get('lon', 'N/A')}\n"
                f" Timezone: {ip_info_json.get('timezone', 'N/A')}\n"
                f" ISP: {ip_info_json.get('isp', 'N/A')}\n"
                f"\n\n======================================\n\n"
            )
        else:
            print(f" DEVELOPED BY >> ChrishSec.com\n\n")
            print("======================================\n\n\n", end='')               
            print(f" Connection Time: {connection_time}")
            print(f" Visited Path: {path}")
            print(f" IP Address: {real_ip}")
            print(f" Browser: {user_agent}")
            print(f" Country: N/A")
            print(f" City: N/A")
            print(f" Lat: N/A")
            print(f" Lon: N/A")
            print(f" Timezone: N/A")
            print(f" ISP: N/A")
            print("\n\n======================================\n\n\n", end='')

            log_data = (
                f" DEVELOPED BY >> ChrishSec.com\n\n\n"
                f"======================================\n\n\n"
                f" Connection Time: {connection_time}\n"
                f" Visited Path: {path}\n"
                f" IP Address: {real_ip}\n"
                f" Browser: {user_agent}\n"
                f" Country: N/A\n"
                f" City: N/A\n"
                f" Lat: N/A\n"
                f" Lon: N/A\n"
                f" Timezone: N/A\n"
                f" ISP: N/A\n"
                f"\n\n======================================\n\n"
            )

        log_file(log_data)

        html_response(client_socket, custom_message_html)

        client_socket.close()

    except ConnectionResetError:
        client_socket.close()

def ip_info(real_ip):
    try:
        api_url = "https://iplookup.chrishsec.com/"
        headers = {
            "Host": "iplookup.chrishsec.com",
            "User-Agent": "CaptureHoney/v2.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://iplookup.chrishsec.com",
            "Referer": "https://iplookup.chrishsec.com/",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Dnt": "1",
            "Sec-Gpc": "1",
            "Te": "trailers",
        }
        data = {
            "ipAddress": real_ip
        }

        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()

        json_match = re.search(r'var jsonData = (\{.*?\});', response.text)
        if json_match:
            json_data = json_match.group(1)
            ip_info_data = json.loads(json_data)

            cleaned_info = json.dumps(ip_info_data, indent=2)
            return cleaned_info
        else:
            return None

    except requests.RequestException as e:
        print(f" [!] Error retrieving IP information: {e}")

    return None

def html_response(client_socket, html_content):
    try:
        response = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{html_content}"
        client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f" [!] Error sending HTML response: {e}")

def main(args):
    try:
        _ = pytz.country_timezones[args.timezone]
    except KeyError:
        print(" [!] Error: Unknown country code specified...")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((args.ip, args.port))
        server_socket.listen(10)
    except Exception as e:
        print(f" [!] Error setting up server socket: {e}")
        sys.exit(1)

    os.system('clear')
    print(f"\n [+] Launching CaptureHoney System - 'IP: {args.ip} Port: {args.port}' - Ready for Intrusion Detection... \n\n")

    try:
        while True:
            client_socket, _ = server_socket.accept()

            threading.Thread(target=handle_client, args=(client_socket,)).start()

    except KeyboardInterrupt:
        print("\n [+] Stopping CaptureHoney.py. Closing server socket...")
        server_socket.close()
        sys.exit(0)
    except Exception as e:
        print(f" [!] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CaptureHoney.py with Command-Line Arguments")
    parser.add_argument("-ip", default="0.0.0.0", help="IP address to bind to")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port number to listen on")
    parser.add_argument("-timezone", default="SG", help="Country code for connection time (default: SG)")
    args = parser.parse_args()
    main(args)
