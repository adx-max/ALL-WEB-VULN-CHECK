print('CREATED BY ANESTUS  UDUME FROM BENTECH SECURITY')
import requests
from bs4 import BeautifulSoup
import re

# Define the target URL
target_url = 'http://example.com'

# Define a list of vulnerabilities to check for
vulnerabilities = {
    'Cross-Site Scripting (XSS)': r'<script>alert\(\'XSS\'\)</script>',
    'SQL Injection': r'You have an error in your SQL syntax',
    'File Inclusion': r'Warning: include\(',
    'Command Injection': r'Executing command:',
    'Remote Code Execution (RCE)': r'vulnerable to RCE'
}

# Send a GET request to the target URL and retrieve the page content
response = requests.get(target_url)
soup = BeautifulSoup(response.content, 'html.parser')

# Find all input fields and check for XSS vulnerabilities
inputs = soup.find_all('input')
for input_field in inputs:
    for vulnerability in vulnerabilities:
        if re.search(vulnerabilities[vulnerability], str(input_field)):
            print(f'{vulnerability} vulnerability detected in input field {input_field["name"]}')

# Check for other vulnerabilities in the page content
for vulnerability in vulnerabilities:
    if re.search(vulnerabilities[vulnerability], str(soup)):
        print(f'{vulnerability} vulnerability detected in page content')

# Check for server-side vulnerabilities
server_response = requests.get(target_url + '/../../../../../../../../../../../etc/passwd')
if server_response.status_code == 200 and 'root:' in server_response.text:
    print('File Inclusion vulnerability detected: /etc/passwd file retrieved')

# Generate a report on detected vulnerabilities
report = f'Vulnerability Report for {target_url}\n\n'
for vulnerability in vulnerabilities:
    if re.search(vulnerabilities[vulnerability], str(soup)):
        report += f'{vulnerability} vulnerability detected in page content\n'
for input_field in inputs:
    for vulnerability in vulnerabilities:
        if re.search(vulnerabilities[vulnerability], str(input_field)):
            report += f'{vulnerability} vulnerability detected in input field {input_field["name"]}\n'
if server_response.status_code == 200 and 'root:' in server_response.text:
    report += 'File Inclusion vulnerability detected: /etc/passwd file retrieved\n'

# Save the report to a file
with open('vulnerability_report.txt', 'w') as f:
    f.write(report)
