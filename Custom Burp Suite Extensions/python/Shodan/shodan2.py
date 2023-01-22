import argparse

# Set up the command line argument parser
parser = argparse.ArgumentParser()
parser.add_argument("--hosts", "-i", required=True, help="List of hosts to check for vulnerabilities")

# Parse the command line arguments
args = parser.parse_args()

# Read the list of hosts from the file specified by the --hosts flag
with open(args.hosts, "r") as f:
    hosts = f.read().splitlines()

#import shodan library
import shodan

# Replace YOUR_API_KEY with your actual API key
api = Shodan("RwhzAhS33ZTwpx8Q9hxAP5ZWxQdsBf1q")

# Iterate over the list of hosts
for host in hosts:
    # Try to look up the host on Shodan
    try:
        result = api.host(host)
        # Determine the file name to use for the host
        if "vulns" in result:
            file_name = f"{host}_vulnerable.txt"
        else:
            file_name = f"{host}.txt"
        # Write the host's IP address, hostnames, and open ports to the file
        with open(file_name, "w") as f:
            f.write(f"Host: {result['ip_str']}\n")
            f.write(f"Hostnames: {','.join(result['hostnames'])}\n")
            f.write(f"Open ports: {','.join(map(str, result['ports']))}\n")
            # Check if the host has known vulnerabilities
            if "vulns" in result:
                f.write(f"Vulnerabilities: {','.join(result['vulns'])}\n")
            else:
                f.write(f"No vulnerabilities found\n")
    except shodan.APIError as e:
        print(f"Error occurred when looking up {host}: {e}")
