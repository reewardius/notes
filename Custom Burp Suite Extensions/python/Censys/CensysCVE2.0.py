import censys.ipv4

# Replace YOUR_API_ID and YOUR_API_SECRET with your actual API ID and API secret
api = censys.ipv4.CensysIPv4(api_id="YOUR_API_ID", api_secret="YOUR_API_SECRET")

# Read the list of hosts from a file
with open("hosts.txt", "r") as f:
    hosts = f.read().splitlines()

# Iterate over the list of hosts
for host in hosts:
    # Try to look up the host on Censys
    try:
        result = api.view(host)
        # Determine the file name to use for the host
        if "vulnerabilities" in result:
            file_name = f"{result['ip']}_vulnerable.txt"
        else:
            file_name = f"{result['ip']}.txt"
        # Write the host's IP address, open ports, and known vulnerabilities to the file
        with open(file_name, "w") as f:
            f.write(f"Host: {result['ip']}\n")
            f.write(f"Open ports: {','.join(map(str, result['protocols']))}\n")
            if "vulnerabilities" in result:
                f.write(f"Vulnerabilities: {','.join(result['vulnerabilities'])}\n")
            else:
                f.write(f"No vulnerabilities found\n")
    except censys.base.CensysUnauthorizedException:
        print(f"Error: invalid API ID or API secret")
    except censys.base.CensysRateLimitExceededException:
        print(f"Error: rate limit exceeded")
    except censys.base.CensysNotFoundException:
        print(f"Error: host not found")
