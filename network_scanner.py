#!/usr/bin/env python

import scapy.all as scapy
import optparse
from datetime import datetime


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP/ IP Range")
    parser.add_option("-i", "--interface", dest="interface", help="Interface to scan")
    user_options = parser.parse_args()[0]
    if not user_options.target:
        print("[-] Please specify target ip/ ip range, refer --help for more information")
    if not user_options.interface:
        print("[-] Please specify target interface, refer --help for more information")
    return user_options


def scan(ip, interface):
    if ip is not None and interface is not None:
        arp_request = scapy.ARP(pdst=ip)  # Creating an arp request packet asking which device has the target ip
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Creating an Ether packet to broadcast to the broadcast mac
        arp_request_broadcast = broadcast / arp_request  # Merging the arp & broadcast packets into a single packet
        print("Scanning " + ip + " on " + interface)
        start_time = datetime.now()
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=interface, inter=0.1, verbose=False)[0]  # Storing the responses of broadcast
        client_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)
        end_time = datetime.now()
        time_taken = end_time - start_time
        print("Scan done in {}".format(time_taken))
        return client_list


def print_result(results_list):
    if results_list is not None:
        print("-----------------------------------------------------\nIP ADDRESS\t\tMAC "
              "ADDRESS\n-----------------------------------------------------")
        for client in results_list:
            print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
try:
    scan_result = scan(options.target, options.interface)
except:
    print("[!] Could not perform scan")
print_result(scan_result)
