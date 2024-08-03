class HwConf:
    def __init__(self, ascii_string):
        self.ascii_string = ascii_string

    def parse_value(self, start_index, length):
        value_str = self.ascii_string[start_index:start_index+length]
        return int(value_str, 10)

    def get_ptz(self):
        return self.parse_value(0, 1)

    def get_horizontal(self):
        return self.parse_value(1, 1)

    def get_vertical(self):
        return self.parse_value(2, 1)

    def get_cds(self):
        return self.parse_value(3, 1)

    def get_picture(self):
        return self.parse_value(4, 1)

    def get_ir_led(self):
        return self.parse_value(5, 1)

    def get_ptz_electrical(self):
        return self.parse_value(6, 1)

    def get_ptz_v_pos(self):
        return self.parse_value(7, 1)

    def get_ptz_h_pos(self):
        return self.parse_value(8, 2)

    def get_ir_cut(self):
        return self.parse_value(10, 1)

    def get_threshold_low_value(self):
        return self.parse_value(11, 4)

    def get_threshold_high_value(self):
        return self.parse_value(15, 4)

    def get_audio_flip(self):
        return self.parse_value(19, 1)

    def get_white_light_negative_flag(self):
        return self.parse_value(20, 1)

    def get_ptz_v_degree(self):
        return self.parse_value(21, 2)

    def get_ptz_h_degree(self):
        return self.parse_value(23, 2)

    def get_ptz_v_speed(self):
        return self.parse_value(25, 3)

    def get_ptz_h_speed(self):
        return self.parse_value(28, 3)

    def get_ptz_v_range(self):
        return self.parse_value(31, 3)

    def get_ptz_h_range(self):
        return self.parse_value(34, 3)

    def get_ptz_v_rate(self):
        return self.parse_value(37, 3)

    def get_ptz_h_rate(self):
        return self.parse_value(40, 3)

    def get_white_led_auto_close(self):
        return self.parse_value(43, 1)

    def get_mic_adjust_volume(self):
        return self.parse_value(44, 2)

    def get_speaker_adjust_volume(self):
        return self.parse_value(46, 2)

    def get_onf_shaking_head_cam(self):
        return self.parse_value(48, 1)

    def get_trace_direction(self):
        return self.parse_value(49, 1)
    
    def display_values(self):
        print("\tPTZ:", self.get_ptz())
        print("\tHorizontal:", self.get_horizontal())
        print("\tVertical:", self.get_vertical())
        print("\tCDS:", self.get_cds())
        print("\tPicture:", self.get_picture())
        print("\tIR LED:", self.get_ir_led())
        print("\tPTZ Electrical:", self.get_ptz_electrical())
        print("\tPTZ V Position:", self.get_ptz_v_pos())
        print("\tPTZ H Position:", self.get_ptz_h_pos())
        print("\tIR Cut:", self.get_ir_cut())
        print("\tThreshold Low Value:", self.get_threshold_low_value())
        print("\tThreshold High Value:", self.get_threshold_high_value())
        print("\tAudio Flip:", self.get_audio_flip())
        print("\tWhite Light Negative Flag:", self.get_white_light_negative_flag())
        print("\tPTZ V Degree:", self.get_ptz_v_degree())
        print("\tPTZ H Degree:", self.get_ptz_h_degree())
        print("\tPTZ V Speed:", self.get_ptz_v_speed())
        print("\tPTZ H Speed:", self.get_ptz_h_speed())
        print("\tPTZ V Range:", self.get_ptz_v_range())
        print("\tPTZ H Range:", self.get_ptz_h_range())
        print("\tPTZ V Rate:", self.get_ptz_v_rate())
        print("\tPTZ H Rate:", self.get_ptz_h_rate())
        print("\tWhite LED Auto Close:", self.get_white_led_auto_close())
        print("\tMic Adjust Volume:", self.get_mic_adjust_volume())
        print("\tSpeaker Adjust Volume:", self.get_speaker_adjust_volume())
        print("\tONF Shaking Head Cam:", self.get_onf_shaking_head_cam())
        print("\tTrace Direction:", self.get_trace_direction())

class DeviceInfo:
    def __init__(self, data):
        self.data = data
        self.field_0 = data[0]
        self.lossrate = data[1]
        self.tfstat = data[2]
        self.internet_lossrate = data[3]
        self.internet_visit = data[4]
        self.field_6 = data[6]
        self.language = data[7]
        self.field_8 = data[8]
        self.is_utc_time = data[9]
        self.day_night_mode = data[10]
        self.alarm_sensitivity = data[11]
        self.ldc_percent = data[14]
        self.baby_cry_enable = data[15]
        self.mic_volume = data[16]
        self.frame_rate = data[20]
        self.encode_mode = data[21]
        self.high_resolution = data[22]
        self.alarm_ring = data[23]
        self.viewpoint_trace = data[24]
        self.voice_ctrl = data[25]
        self.speak_mode = data[26]
        self.lapse_left_time = int.from_bytes(data[28:32], byteorder='little')
        self.total = int.from_bytes(data[40:44], byteorder='little')
        self.free = int.from_bytes(data[44:48], byteorder='little')
        self.silentmode = data[48]
        self.lightmode = data[49]
        self.update_stat = data[50]
        self.update_percent = data[51]
        self.recordmode = data[52]
        self.field_53 = data[53]
        self.mirrorflip = data[54]
        self.ptz_preset = yi_ptz_preset_t(data[56:92])
        self.ptz_info = yi_ptz_info_t(data[68:88])
        self.abnormal_sound = data[88]
        self.abnormal_sound_sensitivity = data[89]
        self.alarm_mode = data[90]
        self.light_switch = data[91]
        self.alarm_sound = data[92]
        self.ability_sets = YI_ABILITY_SETS(data[95:])

    def __str__(self):
        return f"lossrate={self.lossrate}\n\
tfstat={self.tfstat}\n\
internet_lossrate={self.internet_lossrate}\n\
internet_visit={self.internet_visit}\n\
language={self.language}\n\
is_utc_time={self.is_utc_time}\n\
day_night_mode={self.day_night_mode}\n\
alarm_sensitivity={self.alarm_sensitivity}\n\
ldc_percent={self.ldc_percent}\n\
baby_cry_enable={self.baby_cry_enable}\n\
mic_volume={self.mic_volume}\n\
frame_rate={self.frame_rate}\n\
encode_mode={self.encode_mode}\n\
high_resolution={self.high_resolution}\n\
alarm_ring={self.alarm_ring}\n\
viewpoint_trace={self.viewpoint_trace}\n\
voice_ctrl={self.voice_ctrl}\n\
speak_mode={self.speak_mode}\n\
lapse_left_time={self.lapse_left_time}\n\
total={self.total}\n\
free={self.free}\n\
silentmode={self.silentmode}\n\
lightmode={self.lightmode}\n\
update_stat={self.update_stat}\n\
update_percent={self.update_percent}\n\
recordmode={self.recordmode}\n\
mirrorflip={self.mirrorflip}\n\
ptz_preset={self.ptz_preset}\n\
ptz_info={self.ptz_info}\n\
abnormal_sound={self.abnormal_sound}\n\
abnormal_sound_sensitivity={self.abnormal_sound_sensitivity}\n\
alarm_mode={self.alarm_mode}\n\
light_switch={self.light_switch}\n\
alarm_sound={self.alarm_sound}\n\
ability_sets={self.ability_sets}"


class yi_ptz_preset_t:
    def __init__(self, data):
        self.preset_count = data[0]
        self.reserved1 = data[1:4]
        self.preset_value = data[4:12]

    def __str__(self):
        return f"\n\
    preset_count={self.preset_count}\n\
    preset_value={self.preset_value}"


class yi_ptz_info_t:
    def __init__(self, data):
        self.motion_track_switch = data[0]
        self.cruise_switch = data[1]
        self.reserved2 = data[2]
        self.preset_cruise_stay_time = int.from_bytes(data[3:7], byteorder='little')
        self.panoramic_cruise_stay_time = int.from_bytes(data[7:11], byteorder='little')
        self.start_time = int.from_bytes(data[11:15], byteorder='little')
        self.end_time = int.from_bytes(data[15:19], byteorder='little')

    def __str__(self):
        return f"\n\
    motion_track_switch={self.motion_track_switch}\n\
    cruise_switch={self.cruise_switch}\n\
    preset_cruise_stay_time={self.preset_cruise_stay_time}\n\
    panoramic_cruise_stay_time={self.panoramic_cruise_stay_time}\n\
    start_time={self.start_time}\n\
    end_time={self.end_time}"


class YI_ABILITY_SETS:
    def __init__(self, data):
        self.data = data
        self.ability_data = data[:20]

    def __str__(self):
        return f"YI_ABILITY_SETS:\n\
    ability_data={self.ability_data}"
