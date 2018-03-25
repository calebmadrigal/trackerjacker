#!/usr/bin/env python3
# pylint: disable=C0103, W0703, C0111, R0902, R0913

import re
import time
import threading
import subprocess
from functools import reduce
from .common import TJException


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
        trigger_plugin: parsed trigger plugin - a dict in the form {'trigger': trigger function, 'api_version': 1}
        trigger_command: string representing command to run on each trigger match
        trigger_cooldown: seconds between calling the trigger_plugin or trigger_command for a particular device id
        threshold_window: Time window in which the threshold must be reached to cause an alert
        dot11_map: Reference to dott11_mapper.Do11Map object, where the traffic info is stored
    """
    # pylint: disable=E1101, W0613
    def __init__(self,
                 logger,
                 threshold,
                 power,
                 devices_to_watch,
                 aps_to_watch,
                 trigger_plugin,
                 trigger_command,
                 trigger_cooldown,
                 threshold_window,
                 beep_on_trigger,
                 dot11_map):

        self.stop_event = threading.Event()
        self.last_alerted = {}

        # Same as self.arg = arg for every arg (except devices_to_watch and aps_to_watch)
        self.__dict__.update({k: v for k, v in locals().items() if k != 'aps_to_watch'})

        # If no particular things are specified to be watched, assume everything should be watched
        self.track_all = (not aps_to_watch and not devices_to_watch)

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
        if self.track_all:
            self.eval_general_mac_trigger(frame.macs, frame)
            self.eval_general_bssid_trigger(frame.bssid, frame)
            self.eval_general_ssid_trigger(frame.ssid, frame)
        else:
            self.eval_mac_triggers(frame.macs)
            self.eval_bssid_triggers(frame.bssid)
            self.eval_ssid_triggers(frame.ssid)

    def eval_general_mac_trigger(self, macs, frame):
        for mac in macs:
            dev_node = self.dot11_map.get_dev_node(mac)
            if not dev_node:
                continue

            if self.threshold:
                # Calculate bytes received in the alert_window
                bytes_in_window = (self.get_bytes_in_window(dev_node['frames_in']) +
                                   self.get_bytes_in_window(dev_node['frames_out']))
                if bytes_in_window >= self.threshold:
                    self.do_trigger_alert(mac, 'mac', num_bytes=bytes_in_window)

            if self.power and frame.signal_strength > self.power:
                self.do_trigger_alert(mac, 'mac', power=dev_node['signal'])

    def eval_general_bssid_trigger(self, bssid, frame):
        bssid_node = self.dot11_map.get_ap_by_bssid(bssid)
        if self.threshold:
            bytes_in_window = self.get_bytes_in_window(bssid_node['frames'])
            if bytes_in_window >= self.threshold:
                self.do_trigger_alert(bssid, 'bssid', num_bytes=bytes_in_window)

        if self.power and frame.signal_strength >= self.power:
            self.do_trigger_alert(bssid, 'bssid', power=frame.signal_strength)

    def eval_general_ssid_trigger(self, ssid, frame):
        bssid_nodes = self.dot11_map.get_ap_nodes_by_ssid(ssid)
        if bssid_nodes:
            if self.threshold:
                bytes_in_window = reduce(lambda acc, bssid_bytes: acc+bssid_bytes,
                                         [bssid_node['frames'] for bssid_node in bssid_nodes],
                                         0)
                if bytes_in_window >= self.threshold:
                    self.do_trigger_alert(ssid, 'ssid', num_bytes=bytes_in_window)

            if self.power and frame.signal_strength >= self.power:
                self.do_trigger_alert(ssid, 'bssid', power=frame.signal_strength)

    def eval_mac_triggers(self, macs):
        # Only eval macs both on the "to watch" list and in the frame
        devices_to_eval = macs & self.devices_to_watch.keys()
        for mac in devices_to_eval:
            dev_watch_node = self.devices_to_watch[mac]
            dev_node = self.dot11_map.get_dev_node(mac)
            bytes_in_window = 0
            triggered = False

            if dev_node:
                if dev_watch_node['threshold']:
                    # Calculate bytes received in the alert_window
                    bytes_in_window = (self.get_bytes_in_window(dev_node['frames_in']) +
                                       self.get_bytes_in_window(dev_node['frames_out']))
                    if bytes_in_window >= dev_watch_node['threshold']:
                        self.do_trigger_alert(mac, 'mac', num_bytes=bytes_in_window)
                        triggered = True
                if dev_watch_node['power'] and dev_node['signal'] > dev_watch_node['power']:
                    self.do_trigger_alert(mac, 'mac', power=dev_node['signal'])
                    triggered = True

            if not triggered:
                self.logger.debug('Bytes received for {} (threshold: {}) in last {} seconds: {}'
                                  .format(mac, dev_watch_node['threshold'], self.threshold_window, bytes_in_window))

    def eval_bssid_triggers(self, bssid):
        if bssid not in self.bssids_to_watch:
            return

        bssid_watch_node = self.bssids_to_watch[bssid]
        bssid_node = self.dot11_map.get_ap_by_bssid(bssid)
        bytes_in_window = 0
        triggered = False

        if bssid_node:
            if bssid_watch_node['power'] and bssid_node['signal'] >= bssid_watch_node['power']:
                self.do_trigger_alert(bssid, 'bssid', power=bssid_node['signal'])
                triggered = True

            bytes_in_window = self.get_bytes_in_window(bssid_node['frames'])
            if bssid_watch_node['threshold'] and bytes_in_window >= bssid_watch_node['threshold']:
                self.do_trigger_alert(bssid, 'bssid', num_bytes=bytes_in_window)
                triggered = True

        if not triggered:
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
                self.do_trigger_alert(ssid, 'ssid', num_bytes=bytes_in_window)
                return

        self.logger.info('Bytes received for {} in last {} seconds: {}'
                         .format(ssid, self.threshold_window, bytes_in_window))

    def do_trigger_alert(self, dev_id, dev_type, num_bytes=None, power=None):
        """Do alert for triggered item.

        Args:
            alert_msg: Message to log for the alert
        """
        if time.time() - self.last_alerted.get(dev_id, 9999999) < self.trigger_cooldown:
            self.logger.debug('[*] Saw {}, but still in cooldown period ({} seconds)'
                              .format(dev_id, self.trigger_cooldown))
            return

        if num_bytes:
            alert_msg = '[@] Device ({} {}) threshold hit: {} bytes'.format(dev_type, dev_id, num_bytes)
        else:
            alert_msg = '[@] Device ({} {}) seen at power: {}'.format(dev_type, dev_id, power)
        self.logger.info(alert_msg)

        if self.beep_on_trigger:
            print(chr(0x07))

        if self.trigger_plugin:
            try:
                self.trigger_plugin['trigger'](dev_id=dev_id, dev_type=dev_type, num_bytes=num_bytes, power=power)
            except Exception as e:
                raise TJException('Error occurred in trigger plugin: {}'.format(e))

        if self.trigger_command:
            # Start trigger_command in background process - fire and forget
            subprocess.Popen(self.trigger_command)

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
