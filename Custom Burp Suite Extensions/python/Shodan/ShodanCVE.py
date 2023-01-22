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
        # Check if the host has known vulnerabilities
        if "vulns" in result:
            # Write the vulnerabilities found for the host to a file
            with open(f"{host}.txt", "w") as f:
                f.write(f"Vulnerabilities found for {host}:\n")
                for vulnerability in result["vulns"]:
                    f.write(f"{vulnerability}\n")
        else:
            print(f"No vulnerabilities found for {host}")
    except shodan.APIError as e:
        print(f"Error occurred when looking up {host}: {e}")
