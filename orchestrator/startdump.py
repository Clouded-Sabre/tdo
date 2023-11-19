import argparse
import requests
import time
import yaml
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Global constants
RADIUS_USERNAME = "testuser"
RADIUS_PASSWORD = "testpassword"

# Function to start tcpdump on a server
def start_tcpdump(ip, port, tcpdump_options, session_name):
    api_base_url = f"https://{ip}:{port}"

    # Use requests to make API call to start tcpdump
    response = requests.post(
        f"{api_base_url}/start_tcpdump",
        headers={"Content-Type": "application/json"},
        auth=(RADIUS_USERNAME, RADIUS_PASSWORD),
        json={
            "pcap_filename": "capture.pcap",
            "tcpdump_options": tcpdump_options,
            "session_name": session_name,
        },
        verify=False,  # Disable SSL verification for now
    )

    if "success" in response.text:
        print(f"tcpdump started on {ip}:{port}")
    else:
        print(f"Failed to start tcpdump on {ip}:{port}. Response: {response.text}")

# Function to stop tcpdump on a server, download pcap file, and delete server's pcap file
def stop_and_download(ip, port, timestamp, session_name):
    api_base_url = f"https://{ip}:{port}"

    # Use requests to make API call to stop tcpdump
    response_stop = requests.post(
        f"{api_base_url}/stop_tcpdump",
        auth=(RADIUS_USERNAME, RADIUS_PASSWORD),
        json={"session_name": session_name},
        verify=False,  # Disable SSL verification for now
    )

    if "success" in response_stop.text:
        # Use requests to make API call to download pcap file
        response_download = requests.get(
            f"{api_base_url}/download_pcap",
            auth=(RADIUS_USERNAME, RADIUS_PASSWORD),
            json={"session_name": session_name},
            verify=False,  # Disable SSL verification for now
        )

        if response_download.ok:
            # Rename the downloaded pcap file with the timestamp
            with open(f"{session_name}-{ip}-{port}-{timestamp}.pcap", "wb") as f:
                f.write(response_download.content)

            # Use requests to make API call to delete server's pcap file
            response_delete = requests.post(
                f"{api_base_url}/delete_pcap",
                auth=(RADIUS_USERNAME, RADIUS_PASSWORD),
                json={"session_name": session_name},
                verify=False,  # Disable SSL verification for now
            )

            if "success" in response_delete.text:
                print(f"tcpdump stopped on {ip}:{port}, pcap file downloaded and deleted")
            else:
                print(f"Failed to delete pcap file on {ip}:{port} after download. Response: {response_delete.text}")
        else:
            print(f"Failed to download pcap file on {ip}:{port}. HTTP Status Code: {response_download.status_code}")
    else:
        print(f"Failed to stop tcpdump on {ip}:{port}. Response: {response_stop.text}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Start and stop tcpdump on multiple servers.")
    parser.add_argument("--session_name", required=True, help="Session name for tcpdump")
    args = parser.parse_args()

    # Get the current timestamp
    timestamp = time.strftime("%Y%m%d%H%M%S")

    # Load configurations from YAML file
    with open("servers.yaml", "r") as file:
        config = yaml.safe_load(file)

    # Extract default values
    default_port = config["defaults"].get("port", 18443)
    default_tcpdump_options = config["defaults"].get("tcpdump_options", "-i eth0")

    # Loop to start tcpdump on each server
    for server in config["servers"]:
        ip = server["ip"]
        port = server.get("port", default_port)
        tcpdump_options = server.get("tcpdump_options", default_tcpdump_options)

        start_tcpdump(ip, port, tcpdump_options, args.session_name)

    # Wait for user input to stop tcpdump and download pcap files
    input("Press Enter to stop tcpdump and download pcap files (Ctrl+C to exit)...")

    for server in config["servers"]:
        ip = server["ip"]
        port = server.get("port", default_port)

        stop_and_download(ip, port, timestamp, args.session_name)

if __name__ == "__main__":
    main()
