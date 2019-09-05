#!/usr/bin/env python3

import os
import sys
import time
import uuid
import math
import nmap
import socket
import urllib
import requests
import argparse
import traceback
import xml.dom.minidom
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def ip_txt_handle(ips):
    cidr_list = set()
    if 'txt' in ips:
        for ip in open(ips, 'r', encoding = 'utf-8').readlines():
            ip = ip.strip()
            if 'http' in ip:
                ip = ip.replace('http://', '')
                ip = ip.replace('https://', '')
            if '/' in ip:
                ip = ip.replace('/', '')
            cidr_list.add(ip)
        with open(ips, 'w', encoding = 'utf-8') as writer:
            for ip in cidr_list:
                writer.write(ip + '\n')

def ip_xml_handle(xml_path):
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

def nmap_scan(ips, ports, url_path, out_path, str_type, callback = print):
    scan_list = []
    print('Nmap starting.....')
    nm = nmap.PortScanner()
    if 'txt' in ips:
        nm.scan(arguments='-iL %s -p %s -sS -sV -Pn -T4 --open' %(ips, ports))
    else:
        nm.scan(hosts = ips, arguments='-p %s -sS -sV -Pn -T4 --open' %(ports))
    try:
        for host in nm.all_hosts():
            for nmap_proto in nm[host].all_protocols():
                lport = nm[host][nmap_proto].keys()
                lport = sorted(lport)
                for nmap_port in lport:
                    scan_list.append(str(host) + ':' + str(nmap_port))
        print('Nmap scanned.....')
        if str_type == 'port_url':
            print('Path starting.....\n')
            for ip_port in scan_list:
                check(ip_port, url_path, out_path)
            print('Path scanned.....\n')
        else:
            for ip_port in scan_list:
                with open(out_path, 'a') as writer:
                    writer.write(ip_port + '\n')
    except Exception as e:
        print(e)
        pass
    finally:
        pass

def check(host, url_path, out_path):
    try:
        for path in open(url_path).readlines():
            headers = {
                'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                "Connection": "close"
            }
            path = path.strip()
            url = 'http://{0}/{1}'.format(host, path)
            req = requests.get(url,  headers = headers, timeout = 20, verify = False)
            if req.status_code == 200:
                with open(out_path, 'a') as writer:
                    #print(http_url + '\n')
                    writer.write(url + '\n')
                    return True
            return False
    except Exception as e:
        #print(e)
        pass
    finally:
        pass

def main(ips, ports, url_path, out_path, str_type):
    if 'txt' in ips:
        ip_txt_handle(ips)
    port_list = []
    if 'txt' in ports:
        for port in open(ports).readlines():
            port = port.strip()
            port_list.append(port)
        ports =  ",".join(port_list)
    if '.xml' in ips:
        scan_list = ip_xml_handle(ips)
        if str_type == 'port_url':
            for ip_port in scan_list:
                check(ip_port, url_path, out_path)
        else:
            for ip_port in scan_list:
                with open(out_path, 'a') as writer:
                    writer.write(ip_port + '\n')
    else:
        nmap_scan(ips, ports, url_path, out_path, str_type, callback = check)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog = 'scan port', usage = 'python3 ps_masscan.py [options]')
    parser.add_argument('-i', "--ip", type = str, help = '-t 127.0.0.1 or -t ip.txt or ip.xml')
    parser.add_argument('-p', "--ports", type = str, help = '-p 80 or -p port.txt')
    parser.add_argument('-urlpath', "--urlpath", type = str, help ='-urlpath urlpath.txt')
    parser.add_argument('-out', '--out', type = str, help = '-out out.txt')
    parser.add_argument('-type', '--type', type = str, help = '-type port or -type port_url')
    args = parser.parse_args()
    if len(sys.argv) != 11:
        parser.print_help()
        exit()
    main(args.ip, args.ports, args.urlpath, args.out, args.type)