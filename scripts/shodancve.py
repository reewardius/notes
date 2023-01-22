import argparse
import shodan

# Set up the command line argument parser
parser = argparse.ArgumentParser()
parser.add_argument("--hosts", "-i", required=True, help="List of hosts to check for vulnerabilities")

# Parse the command line arguments
args = parser.parse_args()

# Read the list of hosts from the file specified by the --hosts flag
with open(args.hosts, "r") as f:
    hosts = f.read().splitlines()

# Replace YOUR_API_KEY with your actual API key
api = shodan.Shodan("<API_KEY>")

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
            if "os" in result:
                f.write(f"Operating System: {result['os']}\n")
            else:
                f.write(f"Operating System could not be determined\n")
            if "data" in result:
                for data in result["data"]:
                    if "product" in data:
                        if "version" in data:
                            if "port" in data:
                                f.write(f"Product: {data['product']} Version: {data['version']} Port: {data['port']}\n")
                            else:
                                f.write(f"Product: {data['product']} Version: {data['version']} Port: unknown\n")
                        else:
                            if "port" in data:
                                f.write(f"Product: {data['product']} Version: unknown Port: {data['port']}\n")
                            else:
                                f.write(f"Product: {data['product']} Version: unknown Port: unknown\n")
                    if "title" in data:
                        f.write(f"Service: {data['title']}\n")
            else:
                f.write(f"No service or software version information found\n")
            if "asn" in result:
                f.write(f"ASN: {result['asn']}\n")
            else:
                f.write(f"ASN could not be determined\n")
            if "org" in result:
                f.write(f"Organization: {result['org']}\n")
            else:
                f.write(f"Organization could not be determined\n")
            if "ip_str" in result:
                f.write(f"IP: {result['ip_str']}\n")
            else:
                f.write(f"IP could not be determined\n")
    except shodan.APIError as e:
        print(f"Error occurred when looking up {host}: {e}")
