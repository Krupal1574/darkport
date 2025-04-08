#!/usr/bin/env python3

import socket
import sys
import threading
import json
import csv
from tabulate import tabulate
from termcolor import colored
from queue import Queue
import requests
from scapy.all import IP, TCP, sr1

print(r"""
  _____          _____  _  _______   ____  _____ _______ 
 |  __ \   /\   |  __ \| |/ /  __ \ / __ \|  __ \__   __|
 | |  | | /  \  | |__) | ' /| |__) | |  | | |__) | | |   
 | |  | |/ /\ \ |  _  /|  < |  ___/| |  | |  _  /  | |   
 | |__| / ____ \| | \ \| . \| |    | |__| | | \ \  | |   
 |_____/_/    \_\_|  \_\_|\_\_|     \____/|_|  \_\ |_|   

         ⚡ DarkPort — Advanced Python Port Scanner ⚡
             Developer:Krupal Prajapati
""")

from urllib.parse import urlparse

raw_input = input("Enter website URL or IP: ").strip()
parsed_url = urlparse(raw_input if "://" in raw_input else f"http://{raw_input}")
website = parsed_url.hostname


# Choose port range
custom = input("Custom port range? (Y/N): ").lower()
if custom == 'y':
    try:
        start = int(input("Start port: "))
        end = int(input("End port: "))
        ports = list(range(start, end + 1))
    except ValueError:
        print(colored("Invalid input. Using default ports.", "red"))
        ports = [21, 22, 53, 80, 123, 443, 445, 1433, 3306, 3389]
else:
    ports = [21, 22, 53, 80, 123, 443, 445, 1433, 3306, 3389]

# Choose protocol
scan_type = input("Scan TCP, UDP, or Both? (tcp/udp/both): ").lower()

results = []
queue = Queue()

# UDP Payloads for basic service detection
udp_payloads = {
    53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',
    123: b'\x1b' + 47 * b'\0',
    161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\x82\x97\x83\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
}

def tcp_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((website, port))
        sock.close()

        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "Unknown"
            results.append([port, service, 'TCP', colored("Open", "green")])
        else:
            results.append([port, "", 'TCP', colored("Closed", "red")])
    except:
        results.append([port, "", 'TCP', colored("Error", "red")])

def udp_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        payload = udp_payloads.get(port, b'\x00')
        sock.sendto(payload, (website, port))
        try:
            data, _ = sock.recvfrom(1024)
            service = socket.getservbyport(port, 'udp') if port in udp_payloads else "Unknown (response)"
            results.append([port, service, 'UDP', colored("Open", "green")])
        except socket.timeout:
            results.append([port, "", 'UDP', colored("Closed/Filtered", "yellow")])
    except:
        results.append([port, "", 'UDP', colored("Error", "red")])
    finally:
        sock.close()

def worker():
    while not queue.empty():
        port = queue.get()
        if scan_type in ['tcp', 'both']:
            tcp_scan(port)
        if scan_type in ['udp', 'both']:
            udp_scan(port)
        queue.task_done()

# Enqueue ports
for port in ports:
    queue.put(port)

# Launch threads
print(colored(f"\nScanning {website}...\n", "cyan"))
threads = []
for _ in range(100):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    threads.append(thread)

queue.join()

# OS Detection
def os_fingerprint(target):
    pkt = IP(dst=target)/TCP(dport=80, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)

    if resp and resp.haslayer(TCP):
        ttl = resp.ttl
        window = resp.window

        if ttl <= 64:
            os_guess = "Linux/Unix"
        elif ttl <= 128:
            os_guess = "Windows"
        else:
            os_guess = "Unknown"

        return f"{os_guess} (TTL={ttl}, Window={window})"
    return "OS Detection Failed"

os_info = os_fingerprint(website)
print(colored(f"\n[+] Detected OS: {os_info}", "magenta"))

# GeoIP Lookup
def geoip_lookup(ip_or_domain):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_or_domain}").json()
        if response["status"] == "success":
            return {
                "Country": response["country"],
                "City": response["city"],
                "ISP": response["isp"],
                "Org": response["org"],
                "Region": response["regionName"],
                "Lat": response["lat"],
                "Lon": response["lon"]
            }
        else:
            return {"Error": response["message"]}
    except Exception as e:
        return {"Error": str(e)}

geo_info = geoip_lookup(website)
print(colored("\n[+] GeoIP Info:", "cyan"))
for k, v in geo_info.items():
    print(f"  {k}: {v}")

# Display results
print("\n" + tabulate(results, headers=["Port", "Service", "Protocol", "Status"], tablefmt="fancy_grid"))

# Export Options
export = input("\nExport results? (csv/json/both/none): ").lower()
filename_base = website.replace(".", "_")

if export in ["csv", "both"]:
    with open(f"{filename_base}_results.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Service", "Protocol", "Status"])
        for r in results:
            writer.writerow([r[0], r[1], r[2], r[3].replace("\x1b[32m", "").replace("\x1b[31m", "").replace("\x1b[33m", "").replace("\x1b[0m", "")])
    print(colored(f"CSV exported: {filename_base}_results.csv", "blue"))

if export in ["json", "both"]:
    json_data = {
        "scan_results": [
            {
                "port": r[0],
                "service": r[1],
                "protocol": r[2],
                "status": r[3].replace("\x1b[32m", "").replace("\x1b[31m", "").replace("\x1b[33m", "").replace("\x1b[0m", "")
            }
            for r in results
        ],
        "geo_info": geo_info,
        "os_info": os_info
    }
    with open(f"{filename_base}_results.json", "w") as f:
        json.dump(json_data, f, indent=4)
    print(colored(f"JSON exported: {filename_base}_results.json", "blue"))
