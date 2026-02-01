import scapy.all as scapy
from scapy_http import http

#Verilerin nerden alınacağını gösterir.
#sniff = koklama -> Verileri koklama işlemi.
#Store işlemi ile kayıt altına alınıp bunları depolar.
def veriToplama(interface):
    scapy.sniff(iface=interface, store=False, prn=veriAnalizi)


def veriAnalizi(paket):
    #paket.show()
    #Sadece httpli paketleri tutmak için:
    if paket.haslayer(http.HTTPRequest):
        #httpnin sadece raw kısımlarını
        if paket.haslayer(scapy.Raw):
            #rawların load kısmını bulmaya çalışıyor.
            print(paket[scapy.Raw].load)

veriToplama("eth0")
