import argparse
import shodan
from shodan import Shodan

# Set up the command line argument parser
parser = argparse.ArgumentParser()
parser.add_argument("--hosts", "-i", required=True, help="List of hosts to check for vulnerabilities")

# Parse the command line arguments
args = parser.parse_args()

# Replace YOUR_API_KEY with your actual API key
api = shodan.Shodan("RwhzAhS33ZTwpx8Q9hxAP5ZWxQdsBf1q")
# Read the list of hosts from the file specified by the --hosts flag
with open(args.hosts, "r") as f:
    hosts = f.read().splitlines()

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
            # Add Operating System information
            if 'os' in result:
                f.write(f"Operating System: {result['os']}\n")
            # Add Services and software versions
            if 'data' in result:
                for data in result['data']:
                    if 'product' in data:
                        f.write(f"Product: {data['product']} Version: {data['version']}\n")
                    if 'module' in data:
                        f.write(f"Module: {data['module']} Version: {data['version']}\n")
            # Add Network Information
            if 'asn' in result:
                f.write(f"ASN: {result['asn']} Organization: {result['org']}\n")
            if 'subdomains' in result:
                f.write(f"Subdomains: {','.join(result['subdomains'])}\n")
    except shodan.APIError as e:
        print(f"Error occurred when looking up {host}: {e}")
