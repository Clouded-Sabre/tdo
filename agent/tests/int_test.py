import requests
import json
import time
import os

BASE_URL = f"https://{os.environ['VM_IP']}:18443"
USERNAME = "testuser"
PASSWORD = "testpassword"
SESSION_NAME = "test1"

# Function to make a request with basic authentication
def make_request(route, method="GET", json_data=None):
    url = f"{BASE_URL}{route}?session_name={SESSION_NAME}"
    auth = (USERNAME, PASSWORD)
    headers = {"Content-Type": "application/json"} if json_data else {}

    if method == "GET":
        response = requests.get(url, auth=auth, headers=headers, verify=False)  # Use verify=False to ignore SSL warnings
    elif method == "POST":
        response = requests.post(url, auth=auth, headers=headers, data=json.dumps(json_data), verify=False)

    return response.status_code, response.text

# Routes to test
routes = [
    "/test_https",
    "/test_radius",
    "/v1/start_tcpdump",
    "/v1/stop_tcpdump",
    "/v1/get_filesize",
    "/v1/download_pcap",
    "/v1/get_duration",
    "/v1/delete_pcap",
    "/v1/get_storage_space",
]

# Iterate through routes and print the response status and content
for route in routes:
    method = "POST" if "/start_tcpdump" in route or "/stop_tcpdump" in route or "/delete_pcap" in route else "GET"
    json_data = {"pcap_filename": "test.pcap", "tcpdump_options": "-i eth0"} if "/start_tcpdump" in route else None

    status_code, content = make_request(route, method, json_data)
    
    print(f"Route: {route}\nMethod: {method}\nStatus Code: {status_code}\nContent: {content}\n{'=' * 30}")

    # Delay for one second after starting tcpdump to ensure pcap file is created
    if "/start_tcpdump" in route:
        time.sleep(5)
