import os
import sys
from scapy.all import IP, ICMP, sr1, sniff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify
import argparse


# from scapy.all import IP, ICMP, sr, sr1


# Encryption and decryption functions
key = get_random_bytes(16)
print("Key: ", key)


def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return (nonce, ciphertext, tag)


def decrypt_data(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


# Client program
def client_program(dest_ip):
    while True:
        data = input("Enter data to send: ")
        # encrypted_data = encrypt_data(data)
        # print("Encrypted data: ", encrypted_data)
        # print("type: ", type(encrypted_data))
        print("data: ", data)
        print("type: ", type(data))
        print("Sending ICMP message...")

        sr1(IP(dst=dest_ip) / ICMP(type=47) / data, timeout=2, verbose=True)


# Server program
def icmp_filter(pkt):
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 47


def server_program():
    print("Listening for ICMP messages...")
    sniff(
        filter="icmp",
        prn=lambda pkt: print(decrypt_data(pkt[ICMP].load)),
        lfilter=icmp_filter,
    )


# Argparse parses the command line arguments passed to the program
# Option 1: python program.py client [destination_ip]
# Option 2: python program.py server

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP Client/Server message program")
    parser.add_argument(
        "mode", choices=["client", "server"], help="Program mode: client or server"
    )
    parser.add_argument(
        "destination_ip",
        nargs="?",
        help="Destination IP address (required for client mode)",
    )
    args = parser.parse_args()

    if args.mode == "client":
        if not args.destination_ip:
            parser.error("Destination IP address is required for client mode")
        client_program(args.destination_ip)
    elif args.mode == "server":
        server_program()
    else:
        parser.error("Invalid mode")
