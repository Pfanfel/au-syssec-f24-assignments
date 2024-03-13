import argparse
import pickle
from scapy.all import IP, ICMP, sniff, send
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


KEY_LENGTH_BYTES = 32  # 256 bits
NONCE_LENGTH_BYTES = 16  # 128 bits

# key = get_random_bytes(KEY_LENGTH_BYTES)
key = b"\xad\xf6\x86y\x9b\xcaC9\x16\xc8\xc8\x96*\x9bw\x1d\x8eo\xe3\xbdDl\xc0\x96\x93\xe29\xd2\xe4\xd5\x0e\x18"


# Encryption and decryption functions
def encrypt_data(data):
    nonce = get_random_bytes(NONCE_LENGTH_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return (nonce, ciphertext, tag)


def decrypt_data(nonce, ciphertext, tag):
    # 1. create an AES object in GCM mode and pass the nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # 2. decrypt the ciphertext and verify the authentication tag
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


# Client program
def client_program(dest_ip):
    while True:
        input_data = input("Enter data to send: ")
        nonce, ciphertext, tag = encrypt_data(input_data)
        data_to_send = (nonce, ciphertext, tag)
        pickeled_data = pickle.dumps(data_to_send)
        # print("Sending ICMP message...")
        send(IP(dst=dest_ip) / ICMP(type=47) / pickeled_data, verbose=False)


# Server program
def icmp_filter(pkt):
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 47


def server_program():
    print("Listening for ICMP messages...")

    def handle_icmp_packet(pkt):
        # print(f"Received ICMP message: {pkt.show()}")
        pickeled_data = pkt[ICMP].load
        unpickeled_data = pickle.loads(pickeled_data)
        nonce = unpickeled_data[0]
        data = unpickeled_data[1]
        tag = unpickeled_data[2]
        decrypted_data = decrypt_data(nonce, data, tag)
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        print(f"{ip_src} -> {ip_dst}: {decrypted_data}")

    sniff(
        filter="icmp",
        prn=handle_icmp_packet,
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
