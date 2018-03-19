#!/usr/bin/env python3
# pylint: disable=C0103, W0703, C0111, R0902, R0913

import re
import time
import threading
import subprocess
from functools import reduce


class Dot11Tracker:
    """Responsible for tracking access points and devices of interest.

    Args:
        logger: A person who chops down our forest friends for a living
        devices_to_watch: Dict of macs to watch; In this format -
            {'mac1': 315, "mac2": 512}
            where threshold is the number of bytes which, if seen within threshold_window, will cause an alert
            and where power is the minumum RSSI power level which will cause an alert when seen for that mac
            (example usage: to cause an alert when a device is within a certain physical distance).
        aps_to_watch: List of access points in this format - {"ssid1": threshold1, "bssid2": threshold2}
        threshold_window: Time window in which the threshold must be reached to cause an alert
        dot11_map: Reference to dott11_mapper.Do11Map object, where the traffic info is stored
    """
    # pylint: disable=E1101, W0613
    def __init__(self,
                 logger,
                 devices_to_watch,
                 aps_to_watch,
                 threshold_window,
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

    def add_frame(self, frame):
        self.eval_device_triggers(frame.macs)
        self.eval_bssid_triggers(frame.bssid)
        self.eval_ssid_triggers(frame.ssid)

    def eval_device_triggers(self, macs):
        # Only eval macs both on the "to watch" list and in the frame
        devices_to_eval = macs & self.devices_to_watch.keys()
        for mac in devices_to_eval:
            dev_watch_node = self.devices_to_watch[mac]
            dev_node = self.dot11_map.get_dev_node(mac)
            bytes_in_window = 0

            if dev_node:
                if dev_watch_node['power'] and dev_node['signal'] > dev_watch_node['power']:
                    self.do_alert(mac, 'device', '[@] Device ({}) power threshold ({}) hit: {}'
                                  .format(mac, dev_watch_node['power'], dev_node['signal']))
                    continue
                elif dev_watch_node['threshold']:
                    # Calculate bytes received in the alert_window
                    bytes_in_window = (self.get_bytes_in_window(dev_node['frames_in']) +
                                       self.get_bytes_in_window(dev_node['frames_out']))
                    if bytes_in_window >= dev_watch_node['threshold']:
                        self.do_alert(mac, 'device', '[@] Device ({}) threshold hit: {}'.format(mac, bytes_in_window))
                        continue

            self.logger.debug('Bytes received for {} (threshold: {}) in last {} seconds: {}'
                              .format(mac, dev_watch_node['threshold'], self.threshold_window, bytes_in_window))

    def eval_bssid_triggers(self, bssid):
        if bssid not in self.bssids_to_watch:
            return

        bssid_watch_node = self.bssids_to_watch[bssid]
        bssid_node = self.dot11_map.get_ap_by_bssid(bssid)
        bytes_in_window = 0

        if bssid_node:
            bytes_in_window = self.get_bytes_in_window(bssid_node['frames'])
            if bytes_in_window >= bssid_watch_node['threshold']:
                self.do_alert(bssid, 'bssid', '[@] Access Point ({}) threshold hit: {}'
                              .format(bssid, bytes_in_window))
                return

        self.logger.info('Bytes received for {} in last {} seconds: {}'
                         .format(bssid, self.threshold_window, bytes_in_window))

    def eval_ssid_triggers(self, ssid):
        if ssid not in self.ssids_to_watch:
            return

        ssid_watch_node = self.ssids_to_watch[ssid]
        bssid_nodes = self.dot11_map.get_ap_nodes_by_ssid(ssid)
        bytes_in_window = 0

        if bssid_nodes:
            bytes_in_window = reduce(lambda acc, bssid_bytes: acc+bssid_bytes,
                                     [bssid_node['frames'] for bssid_node in bssid_nodes],
                                     0)
            if bytes_in_window >= ssid_watch_node['threshold']:
                self.do_alert(ssid, 'ssid', '[@] Access Point ({}) threshold hit: {}'.format(ssid, bytes_in_window))
                return

        self.logger.info('Bytes received for {} in last {} seconds: {}'
                         .format(ssid, self.threshold_window, bytes_in_window))

    def do_alert(self, dev_id, dev_type, alert_msg):
        """Do alert for triggered item.

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

    def get_bytes_in_window(self, frame_list):
        """Returns number of bytes in a frame_list.

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
