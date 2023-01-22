import shodan

# Read IP addresses from file
with open('ips.txt', 'r') as f:
    ip_list = f.read().splitlines()

# Initialize the Shodan API object
api = shodan.Shodan('YOUR_API_KEY')

# Open files to write output
with open('hosts_found.txt', 'w') as f1, open('hosts_found_formatted.txt', 'w') as f2:
    # Loop through the list of IPs
    for ip in ip_list:
        try:
            # Search Shodan for hostnames associated with IP
            host = api.host(ip)
            
            # Write hostnames to first file
            f1.write(host['hostnames'])
            
            # Write IP and hostnames to second file in specified format
            f2.write(ip + '\n')
            for hostname in host['hostnames']:
                f2.write(hostname + '\n')
            f2.write('=======' + '\n')
            
        except shodan.APIError as e:
            print(f'Error: {e}')
