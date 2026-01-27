def Tarayici(ip):
    res_packet = scapy.ARP(pdst=ip)
    view_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    packet = scapy.srp(fake_packet, timeout=2, verbose=False)[0]

    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        print(packet[0][1].hwsrc)

Tarayici("192.168.1.5")


"""
Bu kodda ip adresi bilinen bir kullanıcının şayet aynı ağda ise MAC adresinin
bulunmasını sağlayan koddur. 
"""
