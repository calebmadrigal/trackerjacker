# Track MAC Addresses using monitor mode

import os
import time
import itertools
import threading
import datetime
import monitor_mode_control
from scapy.all import *

DOT11_DATA_FRAME = 2


class MacTracker:
    def __init__(self, macs_to_watch,
                       iface='wlan0mon',
                       mac_name_map=None,
                       window_secs=10,
                       data_threshold=1,
                       alert_new_macs=True,
                       alert_new_ssids=True,
                       log_file='tracker_jacker.log',
                       ssid_log_file='ssids.txt',
                       mac_log_file='macs_seen.txt',
                       channels_to_monitor=(1, 6, 11),
                       time_per_channel=3,
                       display_packets=False):

        # If 'mon' is in the interface name, assume it's already in interface mode
        # Otherwise, enable monitor mode and call monitor iface name iface + 'mon'
        # E.g. if iface is 'wlan0', create a monitor mode interface called 'wlan0mon'
        if 'mon' in iface:
            self.iface = iface
            self.original_iface_name = None
            print('Assuming iface is already in monitor mode...')
        else:
            self.original_iface_name = iface
            print('Turning on monitor mode for {}'.format(iface))
            self.iface = monitor_mode_control.monitor_mode_on(iface)
            print('Enabled monitor mode on {} as iface name: {}'.format(iface, self.iface))

        # Scapy represents MAC as lowercase
        self.macs_to_watch = set([mac.lower() for mac in macs_to_watch])
        self.mac_name_map = {mac.lower(): name for (mac, name) in mac_name_map.items()} if mac_name_map else {}

        self.window_secs = window_secs
        self.data_threshold = data_threshold
        self.alert_new_macs = alert_new_macs
        self.alert_new_ssids = alert_new_ssids
        self.log_file = log_file
        self.ssid_log_file= ssid_log_file
        self.mac_log_file = mac_log_file
        self.channels_to_monitor = channels_to_monitor
        self.time_per_channel = time_per_channel
        self.display_packets = display_packets

        # If the mac log exists, assume each line in it is a MAC, and add it to the known MACs
        if os.path.exists(self.mac_log_file):
            try:
                with open(self.mac_log_file, 'r') as f:
                    self.seen_macs = set([line.strip() for line in f.readlines()])
                    print('Imported {} seen MACs'.format(len(self.seen_macs)))
            except Exception as e:
                print('Failed to import MACs from file: {}'.format(e))
                self.seen_macs = set()
        else:
            self.seen_macs = set()

        # If the SSID log exists, assume each line in it is an SSID, and add it to the known SSIDs
        if os.path.exists(self.ssid_log_file):
            try:
                with open(self.ssid_log_file, 'r') as f:
                    self.seen_ssids = set([line.strip() for line in f.readlines()])
                    print('Imported {} seen SSIDs'.format(len(self.seen_ssids)))
            except Exception as e:
                print('Failed to import SSIDs from file: {}'.format(e))
                self.seen_ssids = set()
        else:
            self.seen_ssids = set()

        self.packet_lens = {}
        self.packet_lens_lock = threading.Lock()
        self.last_alerted = {}
        self.last_channel_switch_time = 0
        self.current_channel = self.channels_to_monitor[0]
        self.switch_to_channel(self.current_channel)

    def switch_channels_if_time(self):
        if time.time() - self.last_channel_switch_time > self.time_per_channel:
            chans = self.channels_to_monitor
            next_channel = chans[(chans.index(self.current_channel)+1) % len(chans)]
            self.switch_to_channel(next_channel)

            self.current_channel = next_channel
            self.last_channel_switch_time = time.time()

    def switch_to_channel(self, channel_num):
        print('Switching to channel {}'.format(channel_num))
        subprocess.call('iw dev {} set channel {}'.format(self.iface, channel_num), shell=True)

    def get_packet_lens(self, mac):
        if mac not in self.packet_lens:
            self.packet_lens[mac] = []
        return self.packet_lens[mac]

    def get_bytes_in_time_window(self, mac):
        still_in_windows = 0
        with self.packet_lens_lock:
            packet_lens = self.get_packet_lens(mac)
            still_in_window = list(itertools.takewhile(lambda i: time.time()-i[0] < self.window_secs, packet_lens))
            self.packet_lens[mac] = still_in_window
        return sum([i[1] for i in still_in_window])

    def check_for_unseen_ssids(self, frame):
        if frame.haslayer(Dot11Elt):
            ssid = frame[Dot11Elt].info
            if ssid and ssid not in self.seen_ssids:
                self.new_ssid_found(ssid)
                self.seen_ssids |= set([ssid])

    def check_for_unseen_macs(self, macs_in_pkt):
        unseen_macs = (macs_in_pkt - set([None])) - self.seen_macs
        for mac in unseen_macs:
            self.new_mac_found(mac)
            self.seen_macs |= set([mac])

    def new_mac_found(self, mac):
        print('A new MAC found: {}'.format(mac))

        with open(self.mac_log_file, 'a') as f:
            f.write('{}\n'.format(mac))

        self.sound_alarm(beeps=1)

    def new_ssid_found(self, ssid):
        print('A new SSID found: {}'.format(ssid))

        with open(self.ssid_log_file, 'a') as f:
            f.write('channel={}, ssid={}\n'.format(self.current_channel, ssid))

        self.sound_alarm(beeps=1)

    def process_packet(self, pkt):
        if pkt.haslayer(Dot11):
            macs_in_pkt = set([pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3, pkt[Dot11].addr4])

            if self.alert_new_macs:
                self.check_for_unseen_macs(macs_in_pkt)

            if self.alert_new_ssids:
                self.check_for_unseen_ssids(pkt)

            # See if any MACs we care about are here
            matched_macs = self.macs_to_watch & macs_in_pkt
            if matched_macs:
                if self.display_packets:
                    print('\t', pkt.summary())

                with self.packet_lens_lock:
                    for mac in matched_macs:
                        packet_lens = self.get_packet_lens(mac)
                        packet_lens.append((time.time(), len(pkt)))

        self.switch_channels_if_time()

    def sound_alarm(self, beeps=5):
        for i in range(beeps):
            print(chr(0x07))
            time.sleep(0.2)

    def something_detected(self, mac):
        # Only alert every 2 minutes
        if time.time() - self.last_alerted.get(mac, 9999999) < 30:
            return

        device_name = self.mac_name_map.get(mac, mac) # use device name, else use MAC

        msg = '{}: I see {}'.format(datetime.datetime.now(), device_name)
        print(msg)
        with open(self.log_file, 'a') as f:
            f.write(msg + '\n')

        self.sound_alarm()
        self.last_alerted[mac] = time.time()

    def check_loop(self):
        while True:
            for mac in self.macs_to_watch:
                bytes_received_in_time_window = self.get_bytes_in_time_window(mac)
                print('Bytes received in last {} seconds for {}: {}'.format(self.window_secs, mac, bytes_received_in_time_window))
                if bytes_received_in_time_window > self.data_threshold:
                    self.something_detected(mac)

            time.sleep(5)

    def start(self):
        print('Starting monitoring on {}'.format(self.iface))
        t = threading.Thread(target=self.check_loop)
        t.daemon = True
        t.start()

        sniff(iface=self.iface, prn=self.process_packet, store=0)

    def stop(self):
        if self.original_iface_name:
            monitor_mode_control.monitor_mode_off(self.iface)
            print('Disabled monitor mode for interface: {}'.format(self.original_iface_name))

if __name__ == '__main__':
    mac_name_map = {'30:8C:FB:86:CD:20': "Dropcam"}

    motion_detector = MacTracker(list(mac_name_map.keys()), mac_name_map=mac_name_map, iface='wlan0', data_threshold=10000, display_packets=False)

    try:
        motion_detector.start()
    finally:
        motion_detector.stop()

