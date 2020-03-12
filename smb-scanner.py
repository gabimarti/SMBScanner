#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# -----------------------------------------------------------------------------------------------------------
# Name:             smb-scanner.py
# Purpose:          Multithread SMB scanner to search different vulnerabilities.
#                   First version checks only CVE-2020-0796 for SMB v3.11
#
#                   Based on ollypwn/SMBGhost
#                   https://github.com/ollypwn/SMBGhost
#
# Author:           Gabriel Marti Fuentes
# email:            gabimarti at gmail dot com
# GitHub:           https://github.com/gabimarti
# Created:          12/03/2020
# License:          GPLv3
# First Release:    12/03/2020
# Version:          0.1
# -----------------------------------------------------------------------------------------------------------


import argparse
import ipaddress
import socket
import struct
import threading
import time
import urllib.request

########################################################
# CONSTANTS
########################################################
APPNAME = 'SMB Scanner'                                             # Just a name
VERSION = 'v0.1'                                                    # Version
SMB_PORT = 445                                                      # Port to scan
DEFAULT_TIMEOUT = 3.0                                               # Socket timeout
MAX_THREADS = 65535                                                 # Maximum simultaneous threads
TIME_SLEEP = 2.5                                                    # Pause to avoid thread oversaturation
PORT_LIST_SCAN = [SMB_PORT]                                         # List of ports to Scan. For testing multiple ports

# Packet to send and check vuln
PACKET_SMBV311 =  b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00' \
                  b'\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02' \
                  b'\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00' \
                  b'&\x00\x00\x00\x00\x00\x01\x00 ' \
                  b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00' \
                  b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00 '

ENCODING = 'utf-8'                                                  # Encoding for url
VERBOSE_NORMAL = 0
VERBOSE_ERROR = 1
VERBOSE_DEBUG = 2
VERBOSE_LEVELS = ['Normal', 'Error', 'Debug']

BANNER = """ 
  ___ __  __ ___   ___                            
 / __|  \/  | _ ) / __| __ __ _ _ _  _ _  ___ _ _ 
 \__ \ |\/| | _ \ \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___/_|  |_|___/ |___/\__\__,_|_||_|_||_\___|_|    """

########################################################
# VARIABLES
########################################################
threadList = []                                         # List of active threads
verbose = 0                                             # Verbosity disabled, enabled
net_range = ''                                          # Network Range to scan, if not provided, it detects itself
port_list = []                                          # Port list for command line test
timeout = DEFAULT_TIMEOUT                               # Timeout on port connection
total_threads_launched = 0                              # Total threads launched
total_current_threads_running = 0                       # Total threads running at one moment
max_concurrent_threads = 0                              # Store max concurrent threads


########################################################
# CLASSES
########################################################

# Check SMB Vuln at open socket. Returns 1 = Vulnerable, 0 = Not Vulnerable
def check_smb(sock, pkt, verbose):
    try:
        sock.send(pkt)
        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)
        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
            return 0
        else:
            return 1
    except Exception as e:
        if verbose >= VERBOSE_ERROR:
            print('Error in socket conn : {}'.format(e))


# Scan a host (ip), for open ports in port_list. Sends a message to host and wait response to identify Keylogger.
# Can activate more verbosity for errors and control messages, and define a timeout for connection.
class HostScan(threading.Thread):
    def __init__(self, ip, port_list, verbose, timeout):
        threading.Thread.__init__(self)
        self.vuln_ports = []
        self.ports = port_list                              # All ports can be self.ports = range(1, 0xffff + 1)
        self.ip = ip                                        # ip to scan
        self.threads = []                                   # Thread list
        self.verbose = verbose                              # Verbose
        self.timeout = timeout                              # Timeout - alternative: socket.setdefaulttimeout(timeout)
        self.lock = threading.Lock()                        # thread lock
        self.packet = PACKET_SMBV311                        # Packet to send and check vuln

    def scan(self, host, port):
        global total_threads_launched, total_current_threads_running, max_concurrent_threads, keyloggers_found

        # Prevent thread oversaturation
        wait = True
        while wait:
            self.lock.acquire()
            if total_threads_launched < MAX_THREADS:
                self.lock.release()
                wait = False
            else:
                self.lock.release()
                time.sleep(TIME_SLEEP)

        # Increment running threads counter and max concurrent threads
        self.lock.acquire()
        total_threads_launched += 1
        total_current_threads_running += 1
        if total_current_threads_running > max_concurrent_threads:
            max_concurrent_threads = total_current_threads_running
        self.lock.release()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # ipv4 (AF_INET) tcp (SOCK_STREAM)
            sock.settimeout(self.timeout)                                  # Sets timeout

            sock.connect((host, port))

            if len(str(self.packet)) > 0:
                if self.verbose >= VERBOSE_DEBUG:
                    print('Sending packet to {}:{} '.format(host, port))
                vuln = check_smb(sock, self.packet, self.verbose)

                if vuln == 1:
                    self.vuln_ports.append('Host {} Port {} [VULNERABLE]'.format(host, port))
                elif vuln == 0 and self.verbose >= VERBOSE_DEBUG:
                    self.vuln_ports.append('Host {} Port {} [NOT vulnerable]'.format(host, port))

        except Exception as e:
            if self.verbose >= VERBOSE_ERROR:
                print('Host {} Port {} Exception {} '.format(host, port, e))
            pass
        finally:
            sock.close()

        # Decrement running threads counter
        self.lock.acquire()
        total_current_threads_running -= 1
        self.lock.release()

    def write(self):
        for op in self.vuln_ports:
            print(op)

    def run(self):
        self.threads = []
        if self.verbose >= VERBOSE_DEBUG:
            print('Start scan ' + str(self.ip))
        # Enumerate ports list and scan and add to thread
        for i, port in enumerate(self.ports):
            s = threading.Thread(target=self.scan, args=(self.ip, port))
            s.start()
            self.threads.append(s)

        # Finish threads before main thread starts again
        for thread in self.threads:
            thread.join()

        # Write out the ports that are open
        self.write()


# Scan a range of IPs for open ports
# Get CIDR net_gange, List of port_list, message to send, verbosity
class RangeScan(threading.Thread):
    def __init__(self, net_range, port_list, verbose, timeout):
        threading.Thread.__init__(self)
        self.active_hosts = []                                      # IP Host list with at least one open port
        self.ip_net = ipaddress.ip_network(net_range)               # Create the network
        self.all_hosts = list(self.ip_net.hosts())                  # Generate all hosts in network
        self.port_list = port_list                                  # List of ports to scan
        self.threads = []                                           # Thread list
        self.verbose = verbose                                      # Verbose
        self.own_host = socket.gethostname()                        # Client Host name
        self.own_ip = socket.gethostbyname(self.own_host)           # Client Host ip
        self.timeout = timeout                                      # Timeout
        self.hosts_scanned = 0                                      # Total hosts scanned

    def start(self):
        if self.verbose >= 2:
            print('This host is {} ({}) '.format(self.own_host, self.own_ip))

        self.hosts_scanned = 0
        for ip in self.all_hosts:                                   # Scan the network range
            # Thread host port scan
            hs = HostScan(str(ip), self.port_list, self.verbose, self.timeout)
            hs.start()
            self.threads.append(hs)
            self.hosts_scanned += 1

        # Wait to finish threads before main thread starts again
        for thread in self.threads:
            thread.join()


########################################################
# FUNCTIONS
########################################################

# Get the external ip
def get_external_ip():
    external_ip = urllib.request.urlopen('https://ident.me').read().decode(ENCODING)
    return external_ip


# Convert an ip to a CIDR / 24 range
def ip_to_cidr24(ip_to_convert):
    blist = ip_to_convert.split('.')        # split bytes
    blist[3] = '0'                          # changes last byte
    cidr = '.'
    cidr = cidr.join(blist)                 # collect the bytes again
    cidr += '/24'                           # adds mask
    return cidr


# Parse command line parameters
def parse_params():
    parser = argparse.ArgumentParser(description=APPNAME + ' ' + VERSION,
                                     epilog='Scan for SMB Vulnerability.')
    parser.add_argument('-r', '--range', type=str, default="",
                        help='Specify the network range in CIDR format. ' +
                             'If not provided, an attempt is made to autodetect a local class C range. ' +
                             'Example: 192.168.1.0/24')
    parser.add_argument('-w', '--wanauto', action='store_true', default=False,
                        help='If this option is set (and no -r has been specified), ' +
                             'an automatic class C range will be set for the current Wan IP.')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=list(PORT_LIST_SCAN),
                        help='Specify a list of ports to scan. Default value: ' + str(PORT_LIST_SCAN))
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Timeout in seconds on port connection. Default value: ' + str(DEFAULT_TIMEOUT))
    parser.add_argument('-v', '--verbose', type=int, choices=[0,1,2], default=0,
                        help='Increase output verbosity (0=Normal, 1=Error, 2=Debug). Default value: 0')
    args = parser.parse_args()
    return args


def main():
    # Check and parse parameters
    args = parse_params()
    verbose = args.verbose
    net_range = args.range
    wan_auto = args.wanauto
    port_list = args.ports
    timeout = args.timeout

    # Host info
    hostname = socket.gethostname()
    localip = socket.gethostbyname(hostname)
    externalip = get_external_ip()

    print(BANNER)
    print(APPNAME + ' ' + VERSION)
    print('==========================================================')
    print('Verbose level '+str(VERBOSE_LEVELS[verbose]))
    if net_range == "" and not wan_auto:
        net_range = ip_to_cidr24(localip)
        print('Network range to scan (local autodetect) ' + net_range)
    elif net_range == "" and wan_auto:
        net_range = ip_to_cidr24(externalip)
        print('Network range to scan (wan autodetect) ' + net_range)
    else:
        print('Network range to scan ' + net_range)

    print('Ports list ' + str(port_list))
    print('Timeout {} seconds'.format(timeout))

    print('---')
    print('This Host {} : IP local {} : IP wan {}'.format(hostname, localip, externalip))
    print('Scanning ...')
    start = time.perf_counter()
    scanner = RangeScan(net_range, port_list, verbose, timeout)
    scanner.start()
    total_hosts = scanner.hosts_scanned
    total_time = time.perf_counter() - start
    print('Scanned {} hosts at {} in {:6.2f} seconds '.format(total_hosts, args.range, total_time))
    print('Total {} threads launched, and max simultaneous was {} threads'.format(total_threads_launched, max_concurrent_threads))
    if total_current_threads_running > 0:
        print('Something strange happens because the threads running is {} '.format(total_current_threads_running))

if __name__ == '__main__':
    main()

