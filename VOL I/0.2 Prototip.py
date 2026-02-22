from scapy.all import ARP, Ether, srp
import os
import argparse

def MacBulucu(ip):
    res_packet = ARP(pdst=ip)
    view_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet

    packet = srp(fake_packet, timeout=2, verbose=False)[0]

    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        print(packet[0][1].hwsrc)

def ipList():
    os.system("arp -a")

def main():
    parser = argparse.ArgumentParser(prog='gsbfucker')
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="Yerel ağdaki IP adreslerini listeler."
    )

    args = parser.parse_args()

    if args.list:
        ipList()

if __name__ == "__main__":
    main()
