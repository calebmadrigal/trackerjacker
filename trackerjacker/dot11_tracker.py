#!/usr/bin/env python3
# pylint: disable=C0103, W0703, C0111, R0902, R0913

import time
import datetime
import itertools
import threading
import subprocess


class Dot11Tracker:
    # self.__dict__.update(locals()) breaks pylint for member variables, so disable those warnings...
    # pylint: disable=E1101, W0613
    def __init__(self,
                 logger,
                 devices_to_watch,
                 aps_to_watch,
                 threshold_bytes,
                 threshold_window,
                 alert_cooldown,
                 alert_command):

        self.stop_event = threading.Event()

        # Same as self.arg = arg for every arg
        self.__dict__.update(locals())

        self.devices_to_watch = {dev.pop('mac').lower(): dev for dev in devices_to_watch if 'mac' in dev}
        self.devices_to_watch_set = set([mac for mac in self.devices_to_watch.keys()])
        self.aps_to_watch = {ap.pop('bssid').lower(): ap for ap in aps_to_watch if 'bssid' in ap}
        self.aps_to_watch_set = set([bssid for bssid in self.aps_to_watch.keys()])
        #self.aps_ssids_to_watch_set = set([ap['ssid'] for ap in aps_to_watch if 'ssid' in ap])  # TODO: Use this

        if self.aps_to_watch_set:
            self.logger.info('Only monitoring packets from these Access Points: %s', self.aps_to_watch_set)

        if self.devices_to_watch_set:
            self.logger.info('Only monitoring packets from these MACs: %s', self.devices_to_watch_set)

        self.packet_lens = {}
        self.packet_lens_lock = threading.Lock()
        self.last_alerted = {}

    def get_packet_lens(self, mac):
        if mac not in self.packet_lens:
            self.packet_lens[mac] = []
        return self.packet_lens[mac]

    def add_bytes_for_mac(self, mac, num_bytes):
        with self.packet_lens_lock:
            packet_lens = self.get_packet_lens(mac)
            packet_lens.append((time.time(), num_bytes))

    def get_total_bytes_for_mac(self, mac):
        packet_lens = self.get_packet_lens(mac)
        if packet_lens:
            return sum([packet_len for _, packet_len in packet_lens])
        return 0

    def get_bytes_in_time_window(self, mac):
        with self.packet_lens_lock:
            packet_lens = self.get_packet_lens(mac)
            still_in_window = list(itertools.takewhile(lambda i: time.time()-i[0] < self.threshold_window, packet_lens))
            self.packet_lens[mac] = still_in_window
        return sum([i[1] for i in still_in_window])

    def get_threshold(self, mac):
        if mac in self.devices_to_watch and 'threshold' in self.devices_to_watch[mac]:
            return self.devices_to_watch[mac]['threshold']
        return self.threshold_bytes

    def do_alert(self):
        if self.alert_command:
            # Start alert_command in background process - fire and forget
            print(chr(0x07))  # beep
            subprocess.Popen(self.alert_command)

    def mac_of_interest_detected(self, mac):
        if time.time() - self.last_alerted.get(mac, 9999999) < self.alert_cooldown:
            return

        device_name = ' ({})'.format(self.devices_to_watch[mac]['name']) if 'name' in self.devices_to_watch[mac] else ''
        detected_msg = '{}: Detected {}'.format(datetime.datetime.now(), mac) + device_name
        self.logger.info(detected_msg)
        self.do_alert()
        self.last_alerted[mac] = time.time()

    def startTracking(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.startTracking, args=(False,))
            t.daemon = True
            t.start()
            return t

        while not self.stop_event.is_set():
            for mac in self.devices_to_watch_set:
                bytes_received_in_time_window = self.get_bytes_in_time_window(mac)
                self.logger.info('Bytes received in last {} seconds for {}: {}' \
                      .format(self.threshold_window, mac, bytes_received_in_time_window))
                if bytes_received_in_time_window > self.get_threshold(mac):
                    self.mac_of_interest_detected(mac)

            time.sleep(5)

    def stop(self):
        self.stop_event.set()
