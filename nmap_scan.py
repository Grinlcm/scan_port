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