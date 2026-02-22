#Python ile Ağdaki Tüm Cihazları Bulan Scanner
from scapy.all import ARP, Ether, srp
import socket

def network_scan(ip_range):

    print("Ağ taranıyor...")

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=False)[0]

    print("\nBulunan Cihazlar:\n")

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Bilinmiyor"

        print(f"IP: {ip}   MAC: {mac}   İsim: {hostname}")


network_scan("192.168.1.0/24")
