import nmap
import sys
import msgpack
import socket

class MetasploitRPC:
    def __init__(self, password, host='127.0.0.1', port=55553):
        self.host = host
        self.port = port
        self.token = None
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        self.login(password)

    def login(self, password):
        response = self.call('auth.login', [password])
        if response.get('result') == 'success':
            self.token = response.get('token')
        else:
            raise Exception("Authentication failed")

    def call(self, method, args=[]):
        if self.token:
            args = [self.token] + args
        msg = msgpack.packb({"method": method, "args": args})
        self.client.sendall(msg)
        response = self.client.recv(4096)
        return msgpack.unpackb(response, raw=False)

    def get_vulnerabilities(self, host, port):
        return self.call('db.vulns', [host, port])

def parse_nmap_xml(xml_file):
    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(open(xml_file).read())
    return nm

def main(xml_file):
    # Connect to Metasploit
    client = MetasploitRPC('your_password')

    # Parse Nmap XML file
    nmap_scan = parse_nmap_xml(xml_file)

    for host in nmap_scan.all_hosts():
        print(f"Scanning host: {host}")
        for proto in nmap_scan[host].all_protocols():
            for port in nmap_scan[host][proto].keys():
                print(f"Checking port: {port}/{proto}")
                vulnerabilities = client.get_vulnerabilities(host, port)
                if vulnerabilities.get('vulns'):
                    print(f"Vulnerabilities for {host}:{port}")
                    for vuln in vulnerabilities['vulns']:
                        print(f"  Name: {vuln['name']}, Info: {vuln['info']}")
                else:
                    print(f"No vulnerabilities found for {host}:{port}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
        sys.exit(1)
    main(sys.argv[1])
