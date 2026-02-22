from scapy.all
import scapy
import os
import argparse
def MacBulucu(ip):
  res_packet = scapy.ARP(pdst=ip)
  view_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  fake_packet = view_packet / res_packet
  packet = scapy.srp(fake_packet, timeout=2, verbose=False)[0]
  if len(packet) == 0:
    print("MAC bulunamadı")
  else: print(packet[0][1].hwsrc)
    
def ipList():
  os.system("runas /user:Administrator cmd")
  os.system("arp -a")
def main():
  parser = argparse.ArgumentParser(prog='gsbfucker')
  parser.add_argument(
    "-l", "--list", 
    action="store_true", 
    help="Listen on local network and listing all IP addresses." )
  args = parser.parse_args() 
  if args.list:
    ipList()
