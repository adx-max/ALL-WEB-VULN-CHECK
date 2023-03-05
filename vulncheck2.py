print('CREATED BY ANESTUS UDUME FROM BENTECH SECURITY')
import nmap
import subprocess
import os
import argparse
import sys

# Define the command-line arguments
parser = argparse.ArgumentParser(description='Perform a vulnerability assessment and generate a detailed report.')
parser.add_argument('target', metavar='TARGET', type=str, help='The target host or network to scan.')
parser.add_argument('-p', '--port', metavar='PORTS', type=str, default='1-1000', help='The port range to scan (default: 1-1000).')
parser.add_argument('-o', '--output', metavar='OUTPUT', type=str, default='report.txt', help='The output file for the report (default: report.txt).')
args = parser.parse_args()

# Create an nmap scanner object
scanner = nmap.PortScanner()

# Scan the target host or network using nmap
print('Scanning target', args.target, 'on ports', args.port)
scanner.scan(args.target, args.port)

# Create a dictionary to store the detected vulnerabilities
vulnerabilities = {}

# Check for open ports and services
for host in scanner.all_hosts():
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in ports:
            if scanner[host][proto][port]['state'] == 'open':
                service = scanner[host][proto][port]['name']
                if service in ['http', 'https']:
                    # If the service is a web server, check for vulnerabilities using OWASP ZAP
                    print('Checking for vulnerabilities in', service, 'service on port', port, 'using OWASP ZAP')
                    output = subprocess.check_output(['zap-cli', '-p', port, '-t', args.target, '-l', 'HIGH', '-r', 'report.html'])
                    with open('report.html', 'r') as f:
                        report = f.read()
                        if 'alert' in report:
                            vulnerabilities[host] = vulnerabilities.get(host, []) + ['OWASP ZAP detected vulnerabilities in the web service on port ' + port]

# Check for other vulnerabilities using various tools
# You would need to customize this section for your specific environment and vulnerabilities of interest
# For example, to check for Shellshock vulnerability:
# output = subprocess.check_output(['bash', '-c', 'env x=\'() { :;}; echo vulnerable\' bash -c "echo this is a test"'])
# if 'vulnerable' in output:
#     vulnerabilities[host] = vulnerabilities.get(host, []) + ['Shellshock vulnerability detected']

# Generate a report of detected vulnerabilities
with open(args.output, 'w') as f:
    for host, vulns in vulnerabilities.items():
        f.write('Vulnerabilities detected on ' + host + ':\n')
        for vuln in vulns:
            f.write('  - ' + vuln + '\n')
        f.write('\n')
    if not vulnerabilities:
        f.write('No vulnerabilities detected.\n')

print('Report generated at', args.output)
