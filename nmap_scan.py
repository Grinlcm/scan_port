#!/usr/bin/env python3

import os
import sys
import time
import uuid
import math
import nmap
import socket
import requests
import argparse
import traceback
import xml.dom.minidom

def get_ip_port(xml_path):
    scan_list = []
    DOMTree = xml.dom.minidom.parse(xml_path)
    data = DOMTree.documentElement
    nodelist = data.getElementsByTagName('host')
    host_info = {}
    for node in nodelist:
        address_node = node.getElementsByTagName('address')
        addr = address_node[0].getAttribute('addr')
        port_node = node.getElementsByTagName('port')
        for port in port_node:
            portid = port.getAttribute('portid')
            scan_list.append(addr + ':' +portid)
    return scan_list

def nmap_scan(ip_path, ports, url_path, out_path, callback = print):
    scan_list = []
    print('Nmap starting.....')
    nm = nmap.PortScanner()
    nm.scan(arguments='-iL %s -p %s -sS -sV -Pn -T4 --open' %(ip_path, ports))
    try:
        for host in nm.all_hosts():
            for nmap_proto in nm[host].all_protocols():
                lport = nm[host][nmap_proto].keys()
                lport = sorted(lport)
                for nmap_port in lport:
                    scan_list.append(str(host) + ':' + str(nmap_port))
        print('Nmap scanned.....')
        print('Path starting.....')
        for ip_port in scan_list:
            callback(ip_port, url_path, out_path)
        print('Path scanned.....')
    except Exception as e:
        print(e)
        pass
    finally:
        pass

def check(host, url_path, output_path):
    try:
        for path in open(url_path).readlines():
            path = path.strip()
            http_url = 'http://{0}/{1}'.format(host, path)
            https_url = 'https://{0}/{1}'.format(host, path)
            http_req = requests.get(http_url, timeout = 10, allow_redirects = False)
            https_req = requests.get(https_url, timeout = 10, allow_redirects = False)
            if http_req.status_code == 200:
                with open(output_path, 'a') as writer:
                    print(http_url + '\n')
                    writer.write(http_url + '\n')
                    return True
            if https_req.status_code == 200:
                with open(output_path, 'a') as writer:
                    print(https_url + '\n')
                    writer.write(https_url + '\n')
                return True
            return False
    except Exception as e:
        #print(e)
        pass
    finally:
        pass

def main(ip_path, ports, url_path, out_path):
    port_list = []
    if 'txt' in ports:
        for port in open(ports).readlines():
            port = port.strip()
            port_list.append(port)
        ports =  ",".join(port_list)
        #print(ports)
    if '.xml' in ip_path:
        scan_list = get_ip_port(ip_path)
        for ip_port in scan_list:
            check(ip_port, url_path, out_path)
    else:
        nmap_scan(ip_path, ports, url_path, out_path, callback = check)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog = 'scan port', usage = 'python3 ps_masscan.py [options]')
    parser.add_argument('-i', "--ip", type = str, help = '-t 127.0.0.1 or -t ip.txt or ip.xml')
    parser.add_argument('-p', "--ports", type = str, help = '-p 80 or -p port.txt')
    parser.add_argument('-urlpath', "--urlpath", type = str, help ='-urlpath urlpath.txt')
    parser.add_argument('-out', '--out', type = str, help = '-out out.txt')
    args = parser.parse_args()
    if len(sys.argv) != 9:
        parser.print_help()
        exit()
    main(args.ip, args.ports, args.urlpath, args.out)