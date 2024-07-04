import nmap
import sys
from msfrpc import MsfRpcClient

def parse_nmap_xml(xml_file):
    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(open(xml_file).read())
    return nm

def get_vulnerabilities(msf_client, host, port):
    try:
        vulns = msf_client.call('db.vulns', [host, port])
        return vulns['vulns']
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def main(xml_file):
    # Connect to Metasploit
    client = MsfRpcClient('your_password', port=55553)

    # Parse Nmap XML file
    nmap_scan = parse_nmap_xml(xml_file)

    for host in nmap_scan.all_hosts():
        print(f"Scanning host: {host}")
        for proto in nmap_scan[host].all_protocols():
            for port in nmap_scan[host][proto].keys():
                print(f"Checking port: {port}/{proto}")
                vulnerabilities = get_vulnerabilities(client, host, port)
                if vulnerabilities:
                    print(f"Vulnerabilities for {host}:{port}")
                    for vuln in vulnerabilities:
                        print(f"  Name: {vuln['name']}, Info: {vuln['info']}")
                else:
                    print(f"No vulnerabilities found for {host}:{port}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
        sys.exit(1)
    main(sys.argv[1])
