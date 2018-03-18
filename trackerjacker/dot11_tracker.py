#!/usr/bin/env python3
# pylint: disable=C0103, W0703, C0111, R0902, R0913

import re
import time
import datetime
import itertools
import threading
import subprocess
from functools import reduce


class Dot11Tracker:
    # self.__dict__.update(locals()) breaks pylint for member variables, so disable those warnings...
    # pylint: disable=E1101, W0613
    """ Responsible for tracking access points and devices of interest.

    Args:
        logger: A person who chops down our forest friends for a living
        devices_to_watch: Dict of macs to watch; In this format -
            {'mac1': 315, "mac2": 512}
            where threshold is the number of bytes which, if seen within threshold_window, will cause an alert
            and where power is the minumum RSSI power level which will cause an alert when seen for that mac
            (example usage: to cause an alert when a device is within a certain physical distance).
        aps_to_watch: List of access points in this format - {"ssid1": threshold1, "bssid2": threshold2}
        threshold_window: Time window in which the threshold must be reached to cause an alert
        eval_interval: Interval between evaluating triggers
        dot11_map: Reference to dott11_mapper.Do11Map object, where the traffic info is stored
    """
    def __init__(self,
                 logger,
                 devices_to_watch,
                 aps_to_watch,
                 threshold_window,
                 eval_interval,
                 dot11_map):

        self.stop_event = threading.Event()
        self.last_alerted = {}

        # Same as self.arg = arg for every arg (except devices_to_watch and aps_to_watch)
        self.__dict__.update({k: v for k, v in locals().items() if k != 'aps_to_watch'})

        # Creates a map like: {'my_ssid1': {'threshold': 5000, 'last_alert': timestamp}, 'bssid2': {...} }
        self.bssids_to_watch = {}
        self.ssids_to_watch = {}
        for ap_identifier, watch_entry in aps_to_watch.items():
            # Try to determine if the ap_identifier is a bssid or ssid based on pattern, and behave accordingly
            # Note that this means ssids that are named like a bssid will be treated like a bssid instead of an
            # essid, but that's a trade off in terms of simplicity of use I'm willing to make right now.
            if re.match(r'^([a-fA-F0-9]{2}[:|\-]?){6}$', ap_identifier):
                self.bssids_to_watch[ap_identifier.lower()] = watch_entry
            else:
                self.ssids_to_watch[ap_identifier] = watch_entry

    def get_bytes_in_window(self, frame_list):
        """ Returns number of bytes in a frame_list.

        Args:
            frame_list: List in format - [(ts1, num_bytes1), (ts2, num_bytes2)]
        """
        bytes_in_window = 0
        now = time.time()
        for ts, num_bytes in frame_list:
            if (now - ts) > self.threshold_window:
                break
            bytes_in_window += num_bytes
        return bytes_in_window

    def do_alert(self, dev_id, dev_type, alert_msg):
        """ Do alert for triggered item.

        Args:
            alert_msg: Message to log for the alert
        """
        if dev_type == 'ssid':
            dev_index = self.ssids_to_watch
        elif dev_type == 'bssid':
            dev_index = self.bssids_to_watch
        else:
            dev_index = self.devices_to_watch

        trigger_command = dev_index.get(dev_id, {}).get('trigger_command', None)
        trigger_cooldown = dev_index.get(dev_id, {}).get('trigger_cooldown', 30)

        if time.time() - self.last_alerted.get(dev_id, 9999999) < trigger_cooldown:
            self.logger.debug('[*] Saw {}, but still in cooldown period ({} seconds)'.format(dev_id, trigger_cooldown))
            return
        self.logger.info(alert_msg)

        if trigger_command:
            # Start trigger_command in background process - fire and forget
            print(chr(0x07))  # beep
            subprocess.Popen(trigger_command)

        self.last_alerted[dev_id] = time.time()

    def eval_device_triggers(self):
        for mac in self.devices_to_watch:
            dev_watch_node = self.devices_to_watch[mac]
            dev_node = self.dot11_map.get_dev_node(mac)
            bytes_in_window = 0

            if dev_node:
                if dev_watch_node['power'] and dev_node['signal'] > dev_watch_node['power']:
                    self.do_alert(mac, 'device', 'Device ({}) power threshold ({}) hit: {}'
                                  .format(mac, dev_watch_node['power'], dev_node['signal']))
                    continue
                elif dev_watch_node['threshold']:
                    # Calculate bytes received in the alert_window
                    bytes_in_window = (self.get_bytes_in_window(dev_node['frames_in']) +
                                       self.get_bytes_in_window(dev_node['frames_out']))
                    if bytes_in_window >= dev_watch_node['threshold']:
                        self.do_alert(mac, 'device', 'Device ({}) threshold hit: {}'.format(mac, bytes_in_window))
                        continue

            self.logger.debug('Bytes received for {} (threshold: {}) in last {} seconds: {}'
                              .format(mac, dev_watch_node['threshold'], self.threshold_window, bytes_in_window))

    def eval_bssid_triggers(self):
        for bssid in self.bssids_to_watch:
            bssid_watch_node = self.bssids_to_watch[bssid]
            bssid_node = self.dot11_map.get_ap_by_bssid(bssid)
            bytes_in_window = 0

            if bssid_node:
                bytes_in_window = self.get_bytes_in_window(bssid_node['frames'])
                if bytes_in_window >= bssid_watch_node['threshold']:
                    self.do_alert(bssid, 'bssid', 'Access Point ({}) threshold hit: {}'.format(bssid, bytes_in_window))
                    continue

            self.logger.info('Bytes received for {} in last {} seconds: {}'
                             .format(bssid, self.threshold_window, bytes_in_window))

    def eval_ssid_triggers(self):
        for ssid in self.ssids_to_watch:
            ssid_watch_node = self.ssids_to_watch[ssid]
            bssid_nodes = self.dot11_map.get_ap_nodes_by_ssid(ssid)
            bytes_in_window = 0

            if bssid_nodes:
                bytes_in_window = reduce(lambda acc, bssid_bytes: acc+bssid_bytes,
                                         [bssid_node['frames'] for bssid_node in bssid_nodes],
                                         0)
                if bytes_in_window >= ssid_watch_node['threshold']:
                    self.do_alert(ssid, 'ssid', 'Access Point ({}) threshold hit: {}'.format(ssid, bytes_in_window))
                    continue

            self.logger.info('Bytes received for {} in last {} seconds: {}'
                             .format(ssid, self.threshold_window, bytes_in_window))

    def start_tracking(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.start_tracking, args=(False,))
            t.daemon = True
            t.start()
            return t

        while not self.stop_event.is_set():
            self.eval_device_triggers()
            self.eval_ssid_triggers()
            self.eval_bssid_triggers()

            # Make this configurable
            time.sleep(self.eval_interval)

    def stop(self):
        self.stop_event.set()


class Dot11Tracker_old:
    # self.__dict__.update(locals()) breaks pylint for member variables, so disable those warnings...
    # pylint: disable=E1101, W0613
    def __init__(self,
                 logger,
                 devices_to_watch,
                 aps_to_watch,
                 threshold_bytes,
                 threshold_window,
                 trigger_cooldown,
                 trigger_command):

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
        if self.trigger_command:
            # Start trigger_command in background process - fire and forget
            print(chr(0x07))  # beep
            subprocess.Popen(self.trigger_command)

    def mac_of_interest_detected(self, mac):
        if time.time() - self.last_alerted.get(mac, 9999999) < self.trigger_cooldown:
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
