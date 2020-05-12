#!/usr/bin/env python3

import os
import sys
import nmap
import socket
import requests
import argparse
import threading
from queue import Queue
import xml.dom.minidom
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

event = threading.Event()
event.set()
q = Queue(-1)

class multi_thread(threading.Thread):
    def __init__(self, num, q, url_path, out_url):
        threading.Thread.__init__(self)
        self.num = num
        self.q = q
        self.url_path = url_path
        self.out_url = out_url

    def check_url(self, ip_port):
        try:
            print('正在检测:', ip_port)
            for path in open(self.url_path).readlines():
                headers = {
                    'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                    "Connection": "close"
                }
                path = path.strip()
                if path == '/':
                    http_url = 'http://{0}'.format(ip_port)
                    https_url = 'https://{0}'.format(ip_port)
                else:
                    http_url = 'http://{0}/{1}'.format(ip_port, path)
                    https_url = 'https://{0}/{1}'.format(ip_port, path)
                http_req = requests.get(http_url,  headers = headers, verify = False)
                if http_req.status_code == 200:
                    with open(self.out_url, 'a') as writer:
                        writer.write(http_url + '\n')
                    return True
                https_req = requests.get(https_url,  headers = headers, verify = False)
                if https_req.status_code == 200:
                    with open(self.out_url, 'a') as writer:
                        writer.write(https_url + '\n')
                    return True
        except Exception as e:
            print(e)
            pass
        finally:
            pass

    def run(self):
        while event.is_set():
            if self.q.empty():
                event.clear()
            else:
                ip_port = self.q.get()
                self.check_url(ip_port)

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

def nmap_scan(ips, ports, url_path, out_port, out_url, q):
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
        print('Path starting.....\n')
        for ip_port in scan_list:
            with open(out_port, 'a') as writer:
                writer.write(ip_port + '\n')
            q.put(ip_port)
        print('Path scanned.....\n')
    except Exception as e:
        print(e)
        pass
    finally:
        pass

def main(ips, ports, url_path, out_port, out_url, thread_num):
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
        for ip_port in scan_list:
            with open(out_port, 'a') as writer:
                writer.write(ip_port + '\n')
                writer.write(ip_port + '\n')
            q.put(ip_port)
    else:
        nmap_scan(ips, ports, url_path, out_port, out_url, q)
    threads = []
    for num in range(1, thread_num + 1):
        t = multi_thread(num, q, url_path, out_url)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog = 'scan port', usage = 'python3 nmap_scan.py -i 127.0.0.1 -p 80 -path url_path.txt -outport outport.txt -outurl outurl.txt -t 10')
    parser.add_argument('-i', "--ip", type = str, help = '-i 127.0.0.1 or -i ip.txt or ip.xml')    #扫描的目标,可是一个IP,或者一个包含多个IP的txt,或者是用nmap或者masscan扫描的xml结果
    parser.add_argument('-p', "--ports", type = str, help = '-p 80 or -p port.txt')    #扫描的端口,可是一个端口,或者一个包含多个端口的txt,或者是1-65535
    parser.add_argument('-path', "--urlpath", type = str, help ='-path urlpath.txt')   #要检测的url路径
    parser.add_argument('-outport', '--outport', type = str, help = '-outport outport.txt')  #保存所有IP+PORT的文本的路径
    parser.add_argument('-outurl', '--outurl', type = str, help = '-outpurl outurl.txt')  #保存所有可用http或者https所访问的地址文本的路径
    parser.add_argument('-t', '--threads', type = int, help = '-t 10')     #检测url时所用的线程数量
    args = parser.parse_args()
    if len(sys.argv) != 13:
        parser.print_help()
        exit()
    main(args.ip, args.ports, args.urlpath, args.outport, args.outurl, args.threads)