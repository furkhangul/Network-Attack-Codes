import sys
import os
import argparse
from scapy.all import ARP, Ether, srp, conf  # noqa


def root_kontrol():
    if os.geteuid() != 0:
        print("Root yetkisi gerekli! 'sudo python main.py -l' ile çalıştır.")
        sys.exit(1)


def mac_bulucu(ip):
    res_packet = ARP(pdst=ip)
    view_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    packet = srp(fake_packet, timeout=2, verbose=False)[0]
    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        print(f"IP: {ip}  MAC: {packet[0][1].hwsrc}")


def ip_list(network="192.168.1.0/24", iface=None):
    print(f"\n{network} ağı taranıyor...\n")
    if iface:
        conf.iface = iface
    print(f"Kullanılan arayüz: {conf.iface}\n")

    res_packet = ARP(pdst=network)
    view_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    result = srp(fake_packet, timeout=3, verbose=False)[0]

    if len(result) == 0:
        print("Hiçbir cihaz bulunamadı.")
        print("İpucu: Doğru ağ arayüzünü belirtmek için -i parametresini kullan.")
        print("Mevcut arayüzleri görmek için: ip a")
    else:
        print(f"{'IP Adresi':<20} {'MAC Adresi'}")
        print("-" * 40)
        for sent, received in result:
            print(f"{received.psrc:<20} {received.hwsrc}")


def main():
    root_kontrol()

    parser = argparse.ArgumentParser(prog='gsbfucker')
    parser.add_argument(
        "-l", "--list",
        nargs="?",
        const="192.168.1.0/24",
        metavar="NETWORK",
        help="Ağdaki cihazları listeler. Varsayılan: 192.168.1.0/24"
    )
    parser.add_argument(
        "-m", "--mac",
        metavar="IP",
        help="Belirtilen IP adresinin MAC adresini bulur."
    )
    parser.add_argument(
        "-i", "--iface",
        metavar="ARAYUZ",
        help="Kullanılacak ağ arayüzü (örn: eth0, wlan0)"
    )
    args = parser.parse_args()

    if args.list:
        ip_list(args.list, args.iface)
    elif args.mac:
        mac_bulucu(args.mac)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
