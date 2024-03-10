import os

print(os.sys.path)
os.sys.path.append("./.venv/lib/python3.10/site-packages")

import sys
from scapy.all import IP, ICMP, sr1, sniff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify


from scapy.all import IP, ICMP, sr, sr1


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


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ["client", "server"]:
        print("Usage: python program.py [client|server] [destination_ip]")
        sys.exit(1)

    if sys.argv[1] == "client":
        client_program(sys.argv[2])
    else:
        server_program()
