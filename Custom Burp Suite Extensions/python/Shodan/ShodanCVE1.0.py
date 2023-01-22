import shodan

# Replace YOUR_API_KEY with your actual API key
api = shodan.Shodan("RwhzAhS33ZTwpx8Q9hxAP5ZWxQdsBf1q")

# Read the list of hosts from a file
with open("hosts.txt", "r") as f:
    hosts = f.read().splitlines()

# Iterate over the list of hosts
for host in hosts:
    # Try to look up the host on Shodan
    try:
        result = api.host(host)
        # Write the host's IP address, hostnames, and open ports to the file
        with open(f"{host}.txt", "w") as f:
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
