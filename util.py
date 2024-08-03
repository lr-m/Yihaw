import json
import hashlib
from pwn import *
import binascii

def get_hexdump(data, bytes_per_line=16):
    """
    Print the hexdump of a byte string.

    Args:
        data (bytes): The byte string to be hexdumped.
        bytes_per_line (int): Number of bytes to display per line. Default is 16.
    """
    hexdump_response = ''
    for i in range(0, len(data), bytes_per_line):
        line = data[i:i+bytes_per_line]
        hex_bytes = ' '.join(f'{byte:02X}' for byte in line)
        ascii_chars = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in line)
        hexdump_response += f'\033[38;5;240m{i:08X}\033[0m  \033[38;5;244m{hex_bytes.ljust(bytes_per_line*3)}\033[0m  \033[38;5;246m{ascii_chars}\033[0m\n'
    return hexdump_response

def pretty_print_json(json_str):
    try:
        parsed_json = json.loads(json_str)
        pretty_json = json.dumps(parsed_json, indent=4, sort_keys=True)
        print(pretty_json)
    except json.JSONDecodeError as e:
        print("Invalid JSON string:", e)

def gen_sha1_hmac(key, keylen, input, inputlen):
    info("Generating Yi SHA1 HMAC")
    BLOCK_SIZE = 64
    OUTPUT_SIZE = 20
    
    # Part 1
    ipad = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        ipad[i] = 0x36
    for j in range(min(keylen, BLOCK_SIZE)):
        ipad[j] = ipad[j] ^ key[j]

    info(f"First key XOR:\n{get_hexdump(ipad)}")
    
    # Hash the input using SHA-1
    sha1_part1 = hashlib.sha1()
    sha1_part1.update(ipad)
    sha1_part1.update(input)
    output_part1 = sha1_part1.digest()

    info(f"First hash:\n{get_hexdump(output_part1)}")
    
    # Part 2
    opad = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        opad[i] = 0x5c
    for j in range(min(keylen, BLOCK_SIZE)):
        opad[j] = opad[j] ^ key[j]

    info(f"Second key XOR:\n{get_hexdump(opad)}")
    
    # Hash the output from Part 1 using SHA-1
    sha1_part2 = hashlib.sha1()
    sha1_part2.update(opad)
    sha1_part2.update(output_part1)
    output = sha1_part2.digest()

    success(f"Calculated hash:\n{get_hexdump(output)}")
    
    return binascii.hexlify(output).upper()