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
        # Print the host's IP address, open ports, and known vulnerabilities
        print(f"Host: {result['ip']}")
        print(f"Open ports: {','.join(map(str, result['protocols']))}")
        if "vulnerabilities" in result:
            print(f"Vulnerabilities: {','.join(result['vulnerabilities'])}")
        else:
            print("No vulnerabilities found")
    except censys.base.CensysUnauthorizedException:
        print(f"Error: invalid API ID or API secret")
    except censys.base.CensysRateLimitExceededException:
        print(f"Error: rate limit exceeded")
    except censys.base.CensysNotFoundException:
        print(f"Error: host not found")
