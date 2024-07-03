import xml.etree.ElementTree as ET
import csv
import argparse

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr') if host.find('address') is not None else 'Unknown'
        hostnames = [hostname.get('name') for hostname in host.findall('hostnames/hostname')]
        os = host.find('os/osmatch').get('name') if host.find('os/osmatch') is not None else 'Unknown'
        ports = [port.get('portid') for port in host.findall('ports/port')]
        services = [port.find('service').get('name') if port.find('service') is not None else 'Unknown' for port in host.findall('ports/port')]
        
        hosts.append({
            'IP': ip,
            'Hostnames': ', '.join(hostnames),
            'OS': os,
            'Ports': ', '.join(ports),
            'Services': ', '.join(services)
        })
    
    return hosts

def write_to_csv(hosts, csv_file):
    with open(csv_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Hostnames', 'OS', 'Ports', 'Services']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for host in hosts:
            writer.writerow(host)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert Nmap XML to Maltego CSV.')
    parser.add_argument('-i', '--input', required=True, help='Path to Nmap XML input file')
    parser.add_argument('-o', '--output', required=True, help='Path to Maltego CSV output file')
    
    args = parser.parse_args()
    
    hosts = parse_nmap_xml(args.input)
    write_to_csv(hosts, args.output)
                 
