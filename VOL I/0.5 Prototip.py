import sys
import ctypes
import argparse
from scapy.all import ARP, Ether, srp  # noqa

def yonetici_olarak_baslat():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

def mac_bulucu(ip):
    res_packet = ARP(pdst=ip)
    view_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    packet = srp(fake_packet, timeout=2, verbose=False)[0]
    if len(packet) == 0:
        print("MAC bulunamadı")
    else:
        print(f"IP: {ip}  MAC: {packet[0][1].hwsrc}")

def ip_list(network="192.168.1.0/24"):
    print(f"\n{network} ağı taranıyor...\n")
    res_packet = ARP(pdst=network)
    view_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_packet = view_packet / res_packet
    result = srp(fake_packet, timeout=2, verbose=False)[0]

    if len(result) == 0:
        print("Hiçbir cihaz bulunamadı.")
    else:
        print(f"{'IP Adresi':<20} {'MAC Adresi'}")
        print("-" * 40)
        for sent, received in result:
            print(f"{received.psrc:<20} {received.hwsrc}")

def main():
    yonetici_olarak_baslat()

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
    args = parser.parse_args()

    if args.list:
        ip_list(args.list)
    elif args.mac:
        mac_bulucu(args.mac)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
