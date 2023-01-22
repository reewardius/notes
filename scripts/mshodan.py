import shodan
import argparse

# Initialize the command line argument parser
parser = argparse.ArgumentParser(description='Search Shodan for hostnames by IP addresses')
parser.add_argument('input_file', help='File containing the list of IP addresses')
args = parser.parse_args()

# Read IP addresses from file
with open(args.input_file, 'r') as f:
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

# python script.py ips.txt
