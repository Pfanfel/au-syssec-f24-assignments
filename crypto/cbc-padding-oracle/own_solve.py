#!/usr/bin/env python3

# CBC padding oracle attack
# - Michael

import requests
import sys
import re
from Crypto.Util.Padding import pad
import os

BLOCK_SIZE = 16

# oracle needs iv and ciphertext


def send_token_directly(token, base_url):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": token.hex()})
    print(f"res.text:\n{res.text}")
    return res.text


def test_is_padding_invalid(token, base_url):
    new_ciphertext = token
    res = requests.get(
        f"{base_url}/quote/", cookies={"authtoken": new_ciphertext.hex()}
    )
    return res.text == "Data must be padded to 16 byte boundary in CBC mode"


def test_systems_security(base_url):
    new_ciphertext = bytes.fromhex(
        "2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242"
    )
    res = requests.get(
        f"{base_url}/quote/", cookies={"authtoken": new_ciphertext.hex()}
    )
    print(f"[+] done:\n{res.text}")


def request_authtoken(base_url):
    res = requests.get(base_url)
    return res.cookies.get_dict().get("authtoken")


def send_a_short_token(token, base_url):
    res = requests.get(f"{base_url}/quote/", cookies={"authtoken": token.hex()})
    return res


def utf8len(s):
    return len(s.decode("utf-8"))


def xor_block(iv, dec):
    """Performs XOR operation between two blocks and returns the result"""
    assert len(iv) == len(dec)
    result = b""
    for i in range(len(iv)):
        result += bytes([iv[i] ^ dec[i]])
    return result


def oracle(iv, block, base_url):
    new_ciphertext = iv + block
    res = send_a_short_token(new_ciphertext, base_url)
    return (res.text != "Padding is incorrect.") and (
        res.text != "PKCS#7 padding is incorrect."
    )


def single_block_attack_example(block, base_url):
    """Returns the decryption of the given ciphertext block"""

    # zeroing_iv starts out nulled. each iteration of the main loop will add
    # one byte to it, working from right to left, until it is fully populated,
    # at which point it contains the result of DEC(ct_block)
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block, base_url):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block, base_url):
                        continue  # false positive; keep searching
                break
        else:
            raise Exception(
                "no valid padding byte found (is the oracle working correctly?)"
            )

        # print(f"candidate: {candidate}")
        # print(f"pad_val: {pad_val}")

        zeroing_iv[-pad_val] = candidate ^ pad_val
        print(
            f"{zeroing_iv[-pad_val]:>3} = {candidate:>3} ^ {pad_val:>2} -> zeroing_iv: {zeroing_iv}, "
        )

    return zeroing_iv


def full_attack_example(iv, ct, base_url):
    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    # assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = []
    for i in range(0, len(msg), BLOCK_SIZE):
        blocks.append(msg[i : i + BLOCK_SIZE])
    result = b""
    zeroing_iv_blocks = []
    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]

    # [1:] is slicing and it means that we are starting from the second element until the last one
    for ct in blocks[1:]:
        print(f"ct: {ct}")
        zeroing_iv_block = single_block_attack_example(ct, base_url)
        zeroing_iv_blocks.append(zeroing_iv_block)
        # pt = bytes(iv_byte ^ zeroing_iv_block_byte for iv_byte, zeroing_iv_block_byte in zip(iv, zeroing_iv_block))
        print(f"zeroing_iv_blocks: {zeroing_iv_blocks}")
        plain_text_block = xor_block(iv, zeroing_iv_block)
        result += plain_text_block
        print(
            f"{plain_text_block.decode('utf-8')} / {plain_text_block} = {iv} ^ {zeroing_iv_block} -> result: {result}, "
        )
        print(f"result: {result.decode('utf-8')}")
        iv = ct

    return result, zeroing_iv_blocks


def CBC_R_encryption(plaintext, base_url):

    # Using this https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf CBC-R encryption method

    # 1. choose a plaintext message, and divide it into N blocks of b (16) bytes P0, P1, .., PN−1.
    # 2. chose a few random bytes r1, r2, ..., rb, and set Cn−1 = r1|r2|...|rb
    # 3. for i = N − 1 down to 1:
    #    Ci−1 = Pi ⊕ DecriptPaddingOracle(Ci)
    # 4. IV = P0 ⊕ DecriptPaddingOracle(C0)
    # 5. output IV and C =C0|C1|...|Cn−1.
    """
    Encrypts the given plaintext using the CBC-R encryption technique.
    """
    # Convert the plaintext into bytes if it's a string

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    # Ensure the plaintext is a multiple of the block size
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("Plaintext length must be a multiple of the block size.")

    # Divide the plaintext into blocks of b bytes
    plaintext_blocks = [
        plaintext[i : i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)
    ]
    N = len(plaintext_blocks)

    # Choose a few random bytes for the initial ciphertext block
    Cn_1 = bytearray(os.urandom(BLOCK_SIZE))

    # Initialize ciphertext blocks list with the random initial block
    ciphertext_blocks = [Cn_1]

    zeroing_iv_blocks = []

    # Encrypt blocks from N-1 down to 1
    for i in range(N - 1, 0, -1):
        zeroing_iv_block = single_block_attack_example(
            bytes(ciphertext_blocks[0]), base_url
        )
        zeroing_iv_blocks.append(zeroing_iv_block)
        Ci_1 = xor_block(plaintext_blocks[i], zeroing_iv_block)
        ciphertext_blocks.insert(0, Ci_1)

    # Calculate the IV using P0 and the decrypted first ciphertext block
    zeroing_iv_block = single_block_attack_example(
        bytes(ciphertext_blocks[0]), base_url
    )
    zeroing_iv_blocks.append(zeroing_iv_block)
    IV = xor_block(plaintext_blocks[0], zeroing_iv_block)
    print(f"zeroing_iv_blocks: {zeroing_iv_blocks}")
    # Concatenate the ciphertext blocks to form the final ciphertext
    ciphertext = b"".join(ciphertext_blocks)

    return IV, ciphertext


def extract_iv_ct_and_convert_to_byte(token, blocksize):
    # iv split 16 bytes
    iv = token[:blocksize]
    ciphertext = token[blocksize:]
    assert len(iv) == blocksize and len(ciphertext) % blocksize == 0
    iv_bytes = bytes.fromhex(iv)
    ciphertext_bytes = bytes.fromhex(ciphertext)

    return (iv_bytes, ciphertext_bytes)


def extract_string_in_between_quotes(string_with_quotes):
    # The regular expression pattern for a string in quotes
    pattern = r'"(.*?)"'

    # Find all substrings that match the pattern
    matches = re.findall(pattern, string_with_quotes)

    # Return the matches
    return matches


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <base url>", file=sys.stderr)
        exit(1)
    # valid_token = "2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242"

    # Step: 0 Get the token
    requested_token = request_authtoken(sys.argv[1])
    print(f"[+] requested_token: {requested_token}")

    # Step 1: Decript the secret part from the token

    iv, ciphertext = extract_iv_ct_and_convert_to_byte(requested_token, BLOCK_SIZE)

    res, zeroing_iv_blocks = full_attack_example(iv, ciphertext, sys.argv[1])
    print(f"res: {res}")
    print(f"zeroing_iv_blocks: {zeroing_iv_blocks}")
    res_bytes = bytes(res)
    print(res_bytes)
    arr_hex_to_utf8 = res_bytes.decode("utf-8")
    print(arr_hex_to_utf8)

    # Step 2: Extract the secret from the decrypted text (token - "You never figure out that" = secret)

    secret = extract_string_in_between_quotes(arr_hex_to_utf8)
    print(f"secret: {secret}")

    # Step 3: Craft message to send back to server: secret + " plain CBC is not secure!" = plaintext to send back to server
    text_to_send = secret[0] + " plain CBC is not secure!"
    print(f"text_to_send: {text_to_send}")

    # Intermediary text because of timeout in between
    # text_to_send = "I should have used authenticated encryption because ... plain CBC is not secure!"

    # Step 3: Encrypt the crafted message

    ## see https://crypto.stackexchange.com/questions/40312/padding-oracle-attack-encrypting-your-own-message
    # Encript the new message to send by XORing the plaintext_blocK_to_send with the corresponding ciphertextblock to get the ciphertextblock to send i-1

    padded_text_to_send = pad(text_to_send.encode(), BLOCK_SIZE)
    iv_send, ct_send = CBC_R_encryption(padded_text_to_send, sys.argv[1])
    bytes_to_send = iv_send + ct_send

    # Step 4: Send the crafted message back to the server
    returned_quote_with_tags = send_token_directly(bytes_to_send, sys.argv[1])

    # Step 5: Get the quote
    # Stripping the <quote> tags and keeping only the content inside
    stripped_content = returned_quote_with_tags.split("\n")[1]
    print(f"stripped_content: {stripped_content}")


# def experiments():
#     if len(sys.argv) != 2:
#         print(f"usage: {sys.argv[0]} <base url>", file=sys.stderr)
#         exit(1)

# valid_token = "2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242"
# requested_token = request_authtoken(sys.argv[1])
# print(f"[+] requested_token: {requested_token}")
# res_token_test = test_token_is_valid(valid_token, sys.argv[1])
# print(f"[+] token test result: {res_token_test}")
# new_ciphertext_48_byte_len = b"This simple sentence is forty-eight bytes long.."
# new_ciphertext_47_byte_len = b"This simple sentence is forty-seven bytes long."
# print(f" new_ciphertext_47_byte_len: {utf8len(new_ciphertext_47_byte_len)}")
# print(f" new_ciphertext_48_byte_len: {utf8len(new_ciphertext_48_byte_len)}")

# res_padding_test_47 = test_is_padding_invalid(
#     new_ciphertext_47_byte_len, sys.argv[1]
# )
# print(f"[+] res_padding_test (exp true): \n{res_padding_test_47}")
# res_padding_test_48 = test_is_padding_invalid(
#     new_ciphertext_48_byte_len, sys.argv[1]
# )
# print(f"[+] res_padding_test (exp false): \n{res_padding_test_48}")

# change_last_byte(valid_token, sys.argv[1])

# iv split 16 bytes
# iv = bytes.fromhex(valid_token[:BLOCK_SIZE])

# print(f"iv: {iv}")
# ciphertext = bytes.fromhex(valid_token[BLOCK_SIZE:])

# iv = valid_token[:BLOCK_SIZE]
# ciphertext = valid_token[BLOCK_SIZE:]
# # take first block of ciphertext
# first_block = ciphertext[:BLOCK_SIZE]
# zeroing_iv = [0] * BLOCK_SIZE

# # for padding in range(1, BLOCK_SIZE + 1):
# for padding in range(1, BLOCK_SIZE + 1):
#     print(f"padding: {padding}")
#     print(f"zeroing_iv: {zeroing_iv}")
#     padding_iv = [padding ^ b for b in zeroing_iv]  # Why ^ b needed?
#     # From [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20]
#     # To   [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 22]
#     print(f"padding_iv: {padding_iv}")
#     for candidate in range(1, 256):
#         padding_iv[-padding] = candidate
#         new_iv = bytes(padding_iv)
#         # print(f"new_iv: {new_iv}")
#         # new_ciphertext = new_iv + first_block
#         # res = send_a_short_token(new_ciphertext, sys.argv[1])
#         if oracle(new_iv, first_block, sys.argv[1]):
#             print(f"i: {candidate}")

#     zeroing_iv[-padding] = candidate ^ padding  # Why ^ padding needed?

# print(f"zeroing_iv: {zeroing_iv}")

# arr = attack_single_block(first_block, sys.argv[1])
# print(f"arr: {arr}")
# arr_bytes = bytes(arr)
# print(arr_bytes)
# arr_hex_to_utf8 = arr_bytes.decode("utf-8")
# print(arr_hex_to_utf8)

# res = full_attack(iv, ciphertext, sys.argv[1])  # Looks the same all the time
# print(f"res: {res}")
# res = b"\xc39X\x0e\x8f@)\x96\x06'\x82Q?C\x7f?\xfd\xdb\xe39+U4\xf8\xea\x87\xe4\xb6\x0e\x80\x9d\x13cC\x81\xcc\xc3\x0b\xbe\xec\xddb\r\xe2$ea\x8f\\\xc1\x83\xe8\xd7\x13\xe6\x90z\xfc\x81\xcf\xe1\xb07)\x90VZ\r\xbaydm\xc0\x8b\x1f\x18\xa46(\xab\x8a\xb5W\xc1hi\xba\xb4?\xac\x00\x94o\xf6\xae}"
# send_result = send_token_directly(res, sys.argv[1])
# padding is incorrect

# res = single_block_attack_example(first_block, sys.argv[1])
# print(f"res: {res}")
# res_bytes = bytes(res)
# print(res_bytes)
# arr_hex_to_utf8 = res_bytes.decode("utf-8")
# print(arr_hex_to_utf8)

# iv, ciphertext = extract_iv_ct_and_convert_to_byte(requested_token, BLOCK_SIZE)

# res, zeroing_iv_blocks = full_attack_example(iv, ciphertext, sys.argv[1])
# print(f"res: {res}")
# res_bytes = bytes(res)
# print(res_bytes)
# arr_hex_to_utf8 = res_bytes.decode("utf-8")
# print(arr_hex_to_utf8)
# #
# arr_hex_to_utf8 = 'You never figure out that "I should have used authenticated encryption because ...". :)'
# zeroing_iv_blocks = [
#     [230, 44, 88, 234, 239, 128, 186, 117, 214, 80, 63, 59, 229, 164, 13, 227],
#     [178, 255, 217, 94, 26, 227, 216, 136, 185, 115, 163, 175, 158, 26, 148, 30],
#     [147, 84, 91, 193, 99, 26, 179, 180, 54, 15, 93, 19, 240, 44, 81, 97],
#     [140, 210, 173, 250, 142, 193, 182, 80, 132, 77, 113, 226, 122, 129, 202, 197],
#     [115, 175, 176, 13, 55, 0, 92, 12, 152, 32, 104, 46, 187, 89, 86, 150],
#     [87, 73, 123, 3, 95, 119, 14, 11, 228, 3, 107, 101, 85, 146, 147, 3],
# ]

# print(f"zeroing_iv_blocks: {zeroing_iv_blocks}")
# secret = extract_string_in_between_quotes(arr_hex_to_utf8)
# print(f"secret: {secret}")
# text_to_send = secret[0] + " plain CBC is not secure!"
# print(f"text_to_send: {text_to_send}")

# padded_text_to_send = pad(text_to_send.encode(), BLOCK_SIZE)

# encript_plaintext_without_key_2(text_to_send, zeroing_iv_blocks, sys.argv[1])

# WORKING
# iv_send, ct_send = CBC_R_encryption(padded_text_to_send, sys.argv[1])
# bytes_to_send = iv_send + ct_send
# send_token_directly(bytes_to_send, sys.argv[1])

# encripted_text = encript_plaintext_without_key(
#     padded_text_to_send, iv, ciphertext, sys.argv[1]
# )
# send_token_directly(encripted_text, sys.argv[1])
