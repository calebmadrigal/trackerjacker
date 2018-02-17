#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915

import os
import sys
import time
import json
import random
import pprint
import logging
import datetime
import argparse
import itertools
import threading
import subprocess
from contextlib import contextmanager

import device_management

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import scapy.all as scapy
except ModuleNotFoundError:
    logging.getLogger("scapy3k.runtime").setLevel(logging.ERROR)
    import scapy3k.all as scapy


def make_logger(log_path=None, log_level_str='INFO'):
    logger = logging.getLogger('trackerjacker')
    formatter = logging.Formatter('%(asctime)s: (%(levelname)s): %(message)s')
    if log_path:
        log_handler = logging.FileHandler(log_path)
        log_handler.setFormatter(formatter)
        # Print errors to stderr if logging to a file
        stdout_handler = logging.StreamHandler(sys.stderr)
        stdout_handler.setLevel('ERROR')
        stdout_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(stdout_handler)
    else:
        log_handler = logging.StreamHandler(sys.stdout)
        log_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(log_handler)
    log_name_to_level = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
    log_level = log_name_to_level.get(log_level_str.upper(), 20)
    logger.setLevel(log_level)
    return logger


class MacVendorDB:
    def __init__(self, oui_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.txt')):
        self.db = {}
        with open(oui_file, 'r') as f:
            for line in f.readlines():
                mac, vendor = line.split('=', maxsplit=1)
                self.db[mac] = vendor.strip()

    def lookup(self, mac):
        try:
            oui_prefix = mac.upper().replace(':', '')[0:6]
            if oui_prefix in self.db:
                return self.db[oui_prefix]
        except Exception:
            pass

        return ''


class Dot11Frame:
    """ Takes a scapy Dot11 frame and turns it into a format we want. """
    TO_DS = 0x1
    FROM_DS = 0x2

    def __init__(self, frame):
        self.frame = frame
        self.bssid = None
        self.ssid = None
        self.signal_strength = 0
        self.channel = 0

        # DS = Distribution System; wired infrastructure connecting multiple BSSs to form an ESS
        # Needed to determine the meanings of addr1-4
        to_ds = frame.FCfield & Dot11Frame.TO_DS != 0
        from_ds = frame.FCfield & Dot11Frame.FROM_DS != 0
        if to_ds and from_ds:
            self.dst = frame.addr3
            self.src = frame.addr4
            self.macs = {frame.addr1, frame.addr2, frame.addr3, frame.addr4}
        elif to_ds:
            self.src = frame.addr2
            self.dst = frame.addr3
            self.bssid = frame.addr1
            self.macs = {frame.addr2, frame.addr3}
        elif from_ds:
            self.src = frame.addr3
            self.dst = frame.addr1
            self.bssid = frame.addr2
            self.macs = {frame.addr1, frame.addr3}
        else:
            self.dst = frame.addr1
            self.src = frame.addr2
            self.bssid = frame.addr3
            self.macs = {frame.addr1, frame.addr2}

        if (frame.haslayer(scapy.Dot11Elt) and
                (frame.haslayer(scapy.Dot11Beacon) or frame.haslayer(scapy.Dot11ProbeResp))):

            self.ssid = frame[scapy.Dot11Elt].info.decode().replace('\x00', '[NULL]')

        if frame.haslayer(scapy.RadioTap):
            self.signal_strength = frame[scapy.RadioTap].dbm_antsignal

    def type_name(self):
        if self.frame.type == 0:
            return 'management'
        elif self.frame.type == 1:
            return 'control'
        elif self.frame.type == 2:
            return 'data'
        return 'unknown'

    def __str__(self):
        return 'Dot11 (type={}, from={}, to={}, bssid={}, ssid={}, signal_strength={})'.format(
            self.type_name(), self.src, self.dst, self.bssid, self.ssid, self.signal_strength)

    def __repr__(self):
        return self.__str__()


class Dot11Map:
    """ Builds/represents a map of this structure (and saves to yaml files):

    1:  # channel
      "90:35:ab:1c:25:19":  # bssid; Linksys; -75dBm
        ssid: "hacker"
        macs:
          - "00:03:7f:84:f8:09"  # Dropcam; -49dBm
          - "01:00:5e:00:00:fb"  # Apple; -60dBm
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Sony; -67dBm
          - "e8:50:8b:36:5e:bb"  # Unknown; -76dBm
    5:  # channel
      "34:89:ab:c4:15:69":  # bssid; -22dBm
        ssid: "hello-world"
        macs:
          - "b8:27:eb:d6:cc:e9"  # Samsung; -30dBm
          - "d8:49:2f:30:68:17"  # Apple; -29dBm
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Unknown; -25dBm
    """
    MACS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}

    def __init__(self, logger):
        self.logger = logger
        self.map_data = {}
        self.mac_vendor_db = MacVendorDB()
        self.associated_macs = set()
        self.bssid_to_ssid = {}
        self.ssids_seen = set()
        self.macs_seen = set()

    def add_frame(self, channel, dot11_frame):
        if channel not in self.map_data:
            self.map_data[channel] = {'unassociated': {'ssid': None, 'macs': set()}}

        chan_to_bssid = self.map_data[channel]

        if dot11_frame.bssid and dot11_frame.bssid not in Dot11Map.MACS_TO_IGNORE:
            if dot11_frame.bssid not in chan_to_bssid:
                chan_to_bssid[dot11_frame.bssid] = {'ssid': None, 'macs': set(), 'signal': None}
            bssid_node = chan_to_bssid[dot11_frame.bssid]

            # Associate ssid with bssid entry if no ssid has already been set
            if not bssid_node['ssid']:
                if dot11_frame.bssid in self.bssid_to_ssid:
                    bssid_node['ssid'] = self.bssid_to_ssid[dot11_frame.bssid]
                else:
                    bssid_node['ssid'] = dot11_frame.ssid
            else:
                self.bssid_to_ssid[dot11_frame.bssid] = bssid_node['ssid']

            bssid_node['macs'] |= dot11_frame.macs - Dot11Map.MACS_TO_IGNORE - set([dot11_frame.bssid])

            if dot11_frame.signal_strength:
                bssid_node['signal'] = dot11_frame.signal_strength

            # Now that each of these MACs have been associated with this bssid, they are no longer 'unassociated'
            self.associated_macs |= dot11_frame.macs
            self.delete_from_unassociated(dot11_frame.macs - Dot11Map.MACS_TO_IGNORE)
        else:
            bssid_node = chan_to_bssid['unassociated']
            bssid_node['macs'] |= dot11_frame.macs - Dot11Map.MACS_TO_IGNORE - self.associated_macs

        self.check_for_new_stuff(channel, dot11_frame)

    def check_for_new_stuff(self, channel, frame):
        unseen_macs = (frame.macs - set([None])) - self.macs_seen
        self.macs_seen |= unseen_macs
        for mac in unseen_macs:
            self.logger.info('MAC found: {}, Channel: {}'.format(mac, channel))

        if frame.ssid and frame.ssid not in self.ssids_seen:
            self.ssids_seen |= set([frame.ssid])
            self.logger.info('SSID found: {}, BSSID: {}, Channel: {}'.format(frame.ssid, frame.bssid, channel))

    def delete_from_unassociated(self, macs_to_remove):
        for channel in self.map_data:
            self.map_data[channel]['unassociated']['macs'] -= macs_to_remove

    def save_to_file(self, file_path):
        """ Save to YAML file. Note that we manually write yaml to keep sorted ordering. """
        with open(file_path, 'w') as f:
            f.write('# trackerjacker map\n')
            for channel in sorted(self.map_data):
                f.write('{}:  # channel\n'.format(channel))
                for bssid in sorted(self.map_data[channel]):
                    bssid_vendor = self.mac_vendor_db.lookup(bssid)
                    if 'signal' in self.map_data[channel][bssid]:
                        bssid_signal = self.map_data[channel][bssid]['signal']
                        f.write('  "{}":  # bssid; {}; {}dBm\n'.format(bssid, bssid_vendor, bssid_signal))
                    else:
                        f.write('  "{}":  # bssid; {}\n'.format(bssid, bssid_vendor))
                    # Wrote SSID if it exists for this SSID
                    ssid = self.map_data[channel][bssid]['ssid']
                    if not ssid:
                        # In case we hadn't yet got around to updating this bssid's ssid...
                        if bssid in self.bssid_to_ssid:
                            ssid = self.bssid_to_ssid[bssid]
                            self.map_data[channel][bssid]['ssid'] = ssid
                    if ssid:
                        f.write('    ssid: "{}"\n'.format(ssid))
                    f.write('    macs:\n')
                    for mac in sorted([i for i in self.map_data[channel][bssid]['macs'] if i]):
                        mac_vendor = self.mac_vendor_db.lookup(mac)
                        if mac_vendor == '':
                            mac_vendor = "Unknown"
                        f.write('      - "{}"  # {}\n'.format(mac, mac_vendor))

    def load_from_file(self, file_path):
        """ Load from YAML file. """
        try:
            import yaml
            with open(file_path, 'r') as f:
                loaded_map = yaml.load(f.read())

            if loaded_map:
                # Cleanup and make the list of MACs be a set of MACs
                for channel in loaded_map:
                    for bssid in loaded_map[channel]:
                        bssid_node = loaded_map[channel][bssid]
                        if 'ssid' not in bssid_node:
                            bssid_node['ssid'] = None

                        # If key not present or value is None
                        if 'macs' not in bssid_node or not bssid_node['macs']:
                            bssid_node['macs'] = set()
                        else:
                            bssid_node['macs'] = set(bssid_node['macs'])
            else:
                loaded_map = {}

            self.map_data = loaded_map
            return loaded_map

        except Exception as e:
            self.logger.error('Error loading map from file ({}): {}'.format(file_path, e))
            return {}


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

        self.running = False

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
            self.logger.info('Only monitoring packets from these Access Points: %s', self.devices_to_watch_set)

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
        self.logger.info('{}: Detected {} [{}]'.format(datetime.datetime.now(), mac, device_name))
        self.do_alert()
        self.last_alerted[mac] = time.time()

    def startTracking(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.startTracking, args=(False,))
            t.daemon = True
            t.start()
            return t

        self.running = True

        while self.running:
            for mac in self.devices_to_watch_set:
                bytes_received_in_time_window = self.get_bytes_in_time_window(mac)
                self.logger.info('Bytes received in last {} seconds for {}: {}' \
                      .format(self.threshold_window, mac, bytes_received_in_time_window))
                if bytes_received_in_time_window > self.get_threshold(mac):
                    self.mac_of_interest_detected(mac)

            time.sleep(5)

    def stop(self):
        self.running = False


class TrackerJacker:
    # pylint: disable=R0902
    def __init__(self,
                 log_path=None,
                 log_level='INFO',
                 iface=None,
                 channels_to_monitor=None,
                 channel_switch_scheme='default',
                 time_per_channel=2,
                 display_matching_packets=False,
                 display_all_packets=False,
                 # map args
                 do_map=True,
                 map_file='wifi_map.yaml',
                 map_save_period=10,  # seconds
                 # track args
                 do_track=True,
                 devices_to_watch=(),
                 aps_to_watch=(),
                 threshold_bytes=1,
                 threshold_window=10,  # seconds
                 alert_cooldown=30,
                 alert_command=None):

        self.do_map = do_map
        self.do_track = do_track
        self.map_file = map_file
        self.map_save_period = map_save_period
        self.time_per_channel = time_per_channel
        self.display_matching_packets = display_matching_packets
        self.display_all_packets = display_all_packets
        self.mac_vendor_db = MacVendorDB()

        self.need_to_disable_monitor_mode_on_exit = False
        self.last_channel_switch_time = 0
        self.num_msgs_received_this_channel = 0
        self.current_channel = 1

        self.logger = make_logger(log_path, log_level)
        self.configure_interface(iface)
        self.configure_channels(channels_to_monitor, channel_switch_scheme)

        self.devices_to_watch_set = set([dev['mac'].lower() for dev in devices_to_watch if 'mac' in dev])
        self.aps_to_watch_set = set([ap['bssid'].lower() for ap in aps_to_watch if 'bssid' in ap])

        if self.do_map:
            self.logger.info('Map output file: %s', self.map_file)
            self.dot11_map = Dot11Map(self.logger)
            if os.path.exists(self.map_file):
                self.dot11_map.load_from_file(self.map_file)
            self.map_last_save = time.time()

        if self.do_track:
            self.dot11_tracker = Dot11Tracker(self.logger, devices_to_watch, aps_to_watch,
                                              threshold_bytes, threshold_window, alert_cooldown, alert_command)

    def configure_interface(self, iface):
        # If no device specified, see if there is a device already in monitor mode, and go with it...
        if not iface:
            monitor_mode_iface = device_management.find_first_monitor_interface()
            if monitor_mode_iface:
                self.iface = monitor_mode_iface
                self.logger.debug('Using monitor mode interface: %s', self.iface)
            else:
                self.logger.error('Please specify interface with -i switch')
                sys.exit(1)

        # If specified interface is already in monitor mode, do nothing... just go with it
        elif device_management.is_monitor_mode_device(iface):
            self.iface = iface
            self.logger.debug('Interface %s is already in monitor mode...', iface)

        # Otherwise, try to put specified interface into monitor mode, but remember to undo that when done...
        else:
            try:
                device_management.monitor_mode_on(iface)
                self.iface = iface
                self.need_to_disable_monitor_mode_on_exit = True
                self.logger.debug('Enabled monitor mode on %s', iface)
            except Exception:
                # If we fail to find the specified (or default) interface, look to see if there is a monitor interface
                self.logger.warning('Could not enable monitor mode on enterface: %s', iface)
                mon_iface = device_management.find_first_monitor_interface()
                if mon_iface:
                    self.iface = mon_iface
                    self.logger.debug('Going with interface: %s', self.iface)
                else:
                    self.logger.error('And could not find a monitor interface')
                    sys.exit(1)

    def configure_channels(self, channels_to_monitor, channel_switch_scheme):
        # Find supported channels
        self.supported_channels = device_management.get_supported_channels(self.iface)
        if not self.supported_channels:
            self.logger.error('Interface not found: %s', self.iface)
            sys.exit(1)

        self.logger.info('Channels available on %s: %s', self.iface, self.supported_channels)

        if channels_to_monitor:
            channels_to_monitor_set = set([int(c) for c in channels_to_monitor])
            if len(channels_to_monitor_set & set(self.supported_channels)) != len(channels_to_monitor_set):
                self.logger.error('Not all of channels to monitor are supported by %s', self.iface)
                self.restore_interface()
                sys.exit(1)
            self.channels_to_monitor = channels_to_monitor
            self.current_channel = self.channels_to_monitor[0]
        else:
            self.channels_to_monitor = self.supported_channels
            self.current_channel = self.supported_channels[0]

        if channel_switch_scheme == 'default':
            if self.do_map:
                channel_switch_scheme = 'round_robin'
            else:
                channel_switch_scheme = 'traffic_based'

        if channel_switch_scheme == 'traffic_based':
            self.channel_switch_func = self.switch_channel_based_on_traffic

            # Start with a high count for each channel, so each channel is more likely to be tried
            # at least once before having the true count for it set
            self.msgs_per_channel = {c: 100000 for c in self.channels_to_monitor}
        else:
            self.channel_switch_func = self.switch_channel_round_robin

        self.last_channel_switch_time = 0
        self.num_msgs_received_this_channel = 0
        self.switch_to_channel(self.current_channel, force=True)
        self.channel_switcher_thread()

    def channel_switcher_thread(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.channel_switcher_thread, args=(False,))
            t.daemon = True
            t.start()
            return t

        # Only worry about switching channels if we are monitoring 2 or more
        if len(self.channels_to_monitor) > 1:
            while True:
                time.sleep(self.time_per_channel)
                self.channel_switch_func()
                self.last_channel_switch_time = time.time()

    def get_next_channel_based_on_traffic(self):
        total_count = sum((count for channel, count in self.msgs_per_channel.items()))
        percent_to_channel = {count/total_count: channel for channel, count in self.msgs_per_channel.items()}

        percent_sum = 0
        sum_to_reach = random.random()
        for percent, channel in percent_to_channel.items():
            percent_sum += percent
            if percent_sum >= sum_to_reach:
                return channel

        return random.sample(self.channels_to_monitor, 1)[0]

    def switch_channel_based_on_traffic(self):
        next_channel = self.get_next_channel_based_on_traffic()

        # Don't ever set a channel to a 0% probability of being hit again
        if self.num_msgs_received_this_channel == 0:
            self.num_msgs_received_this_channel = min(self.msgs_per_channel.values())

        self.msgs_per_channel[self.current_channel] = self.num_msgs_received_this_channel
        self.num_msgs_received_this_channel = 0
        self.switch_to_channel(next_channel)

    def switch_channel_round_robin(self):
        chans = self.channels_to_monitor
        next_channel = chans[(chans.index(self.current_channel)+1) % len(chans)]
        self.switch_to_channel(next_channel)

    def switch_to_channel(self, channel_num, force=False):
        self.logger.debug('Switching to channel %s', channel_num)
        if channel_num == self.current_channel and not force:
            return
        device_management.switch_to_channel(self.iface, channel_num)
        self.current_channel = channel_num

    def process_packet(self, pkt):
        if pkt.haslayer(scapy.Dot11):
            dot11_frame = Dot11Frame(pkt)
            self.num_msgs_received_this_channel += 1

            if self.display_all_packets:
                print('\t', pkt.summary())

            if self.aps_to_watch_set:
                if dot11_frame.bssid not in self.aps_to_watch_set:
                    print('packet not in aps to watch')
                    return

            # See if any MACs we care about are here
            matched_macs = self.devices_to_watch_set & dot11_frame.macs
            if matched_macs:
                if self.display_matching_packets and not self.display_all_packets:
                    print('\t', pkt.summary())

                if self.do_track:
                    num_bytes_in_pkt = len(pkt)
                    for mac in matched_macs:
                        self.dot11_tracker.add_bytes_for_mac(mac, num_bytes_in_pkt)

            if self.do_map:
                self.dot11_map.add_frame(int(self.current_channel), dot11_frame)
                if time.time() - self.map_last_save >= self.map_save_period:
                    self.dot11_map.save_to_file(self.map_file)
                    self.map_last_save = time.time()

    def restore_interface(self):
        if self.need_to_disable_monitor_mode_on_exit:
            device_management.monitor_mode_off(self.iface)
            self.logger.debug('Disabled monitor mode for interface: %s', self.iface)

    def start(self):
        self.logger.debug('Starting monitoring on %s', self.iface)

        if self.do_track:
            self.dot11_tracker.startTracking()

        scapy.sniff(iface=self.iface, prn=self.process_packet, store=0)

    def stop(self):
        self.restore_interface()

        if self.do_map:
            # Flush map to disk
            self.dot11_map.save_to_file(self.map_file)

        if self.do_track:
            self.dot11_tracker.stop()


def get_config():
    # Default config
    config = {'log_path': None,
              'log_level': 'INFO',
              'iface': None,
              'devices_to_watch': [],
              'aps_to_watch': [],
              'threshold_window': 10,
              'do_map': True,
              'do_track': True,
              'map_file': 'wifi_map.yaml',
              'map_save_period': 10,
              'threshold_bytes': 1,
              'alert_cooldown': 30,
              'alert_command': None,
              'channels_to_monitor': None,
              'channel_switch_scheme': 'round_robin',
              'time_per_channel': 2,
              'display_matching_packets': False,
              'display_all_packets': False}

    parser = argparse.ArgumentParser()
    # Modes
    parser.add_argument('--map', action='store_true', dest='do_map',
                        help='Map mode - output map to wifi_map.yaml')
    parser.add_argument('--track', action='store_true', dest='do_track',
                        help='Track mode')
    parser.add_argument('--monitor-mode-on', action='store_true', dest='do_enable_monitor_mode',
                        help='Enables monitor mode on the specified interface and exit')
    parser.add_argument('--monitor-mode-off', action='store_true', dest='do_disable_monitor_mode',
                        help='Disables monitor mode on the specified interface and exit')
    parser.add_argument('--set-channel', metavar='CHANNEL', dest='set_channel', nargs=1,
                        help='Set the specified wireless interface to the specified channel and exit')
    parser.add_argument('--mac-lookup', type=str, dest='mac_lookup',
                        help='Lookup the vendor of the specified MAC address and exit')
    parser.add_argument('--print-default-config', action='store_true', dest='print_default_config',
                        help='Print boilerplate config file and exit')

    # Normal switches
    parser.add_argument('-i', '--interface', type=str, dest='iface',
                        help='Network interface to use; if empty, try to find monitor inferface')
    parser.add_argument('-m', '--macs', type=str, dest='devices_to_watch',
                        help='MAC(s) to track; comma separated for multiple')
    parser.add_argument('-a', '--access-points', type=str, dest='aps_to_watch',
                        help='Access point(s) to track - specified by BSSID; comma separated for multiple')
    parser.add_argument('--channels-to-monitor', type=str, dest='channels_to_monitor',
                        help='Channels to monitor; comma separated for multiple')
    parser.add_argument('-t', '--threshold', type=int, dest='threshold_bytes',
                        help='Threshold of packets in time window which causes alert')
    parser.add_argument('-w', '--time-window', type=int, dest='threshold_window',
                        help='Time window (in seconds) which alert threshold is applied to')
    parser.add_argument('--alert-command', type=str, dest='alert_command',
                        help='Command to execute upon alert')
    parser.add_argument('--display-all-packets', action='store_true', dest='display_all_packets',
                        help='If true, displays all packets matching filters')
    parser.add_argument('--log-path', type=str, dest='log_path', default=None,
                        help='Log path; default is stdout')
    parser.add_argument('--log-level', type=str, dest='log_level', default='INFO',
                        help='Log level; Options: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    parser.add_argument('-c', '--config', type=str, dest='config',
                        help='Path to config json file; For example config file, use --print-default-config')

    # vars converts from namespace to dict
    args = parser.parse_args()

    @contextmanager
    def handle_interface_not_found():
        if not args.iface:
            print('You must specify the interface with the -i paramter', file=sys.stderr)
            sys.exit(1)
        try:
            yield
        except FileNotFoundError:
            print('Couldn\'t find requested interface: {}'.format(args.iface), file=sys.stderr)
            sys.exit(1)

    if args.do_enable_monitor_mode:
        with handle_interface_not_found():
            device_management.monitor_mode_on(args.iface)
            print('Enabled monitor mode on {}'.format(args.iface))
            sys.exit(0)
    elif args.do_disable_monitor_mode:
        with handle_interface_not_found():
            device_management.monitor_mode_off(args.iface)
            print('Disabled monitor mode on {}'.format(args.iface))
            sys.exit(0)
    elif args.mac_lookup:
        vendor = MacVendorDB().lookup(args.mac_lookup)
        if vendor:
            print(vendor)
        else:
            print('Vendor for {} not found'.format(args.mac_lookup), file=sys.stderr)
        sys.exit(0)
    elif args.print_default_config:
        print(json.dumps(config, indent=4, sort_keys=True))
        sys.exit(0)
    elif args.set_channel:
        with handle_interface_not_found():
            channel = args.set_channel[0]
            device_management.switch_to_channel(args.iface, channel)
            print('Set channel to {} on {}'.format(channel, args.iface))
            sys.exit(0)

    macs_from_config = []
    aps_from_config = []

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_from_file = json.loads(f.read())

            # If there are any keys defined in the config file not allowed, error out
            invalid_keys = set(config_from_file.keys()) - set(config.keys())
            if invalid_keys:
                print('Invalid keys found in config file: {}'.format(invalid_keys), file=sys.stderr)
                sys.exit(1)

            macs_from_config = [{'mac': dev} if isinstance(dev, str) else dev
                                for dev in config_from_file.pop('devices_to_watch', [])]
            aps_from_config = [{'bssid': ap} if isinstance(ap, str) else ap
                               for ap in config_from_file.pop('aps_to_watch', [])]

            config.update(config_from_file)
            print('Loaded configuration from {}'.format(args.config))

        except (IOError, OSError, json.decoder.JSONDecodeError) as e:
            print('Error loading config file ({}): {}'.format(args.config, e), file=sys.stderr)
            sys.exit(1)

    macs_from_args = []
    aps_from_args = []

    if args.devices_to_watch:
        macs_from_args = [{'mac': mac} for mac in args.devices_to_watch.split(',')]
    if args.aps_to_watch:
        macs_from_args = [{'bssid': bssid} for bssid in args.aps_to_watch.split(',')]

    non_config_args = ['config', 'devices_to_watch', 'aps_to_watch', 'do_enable_monitor_mode',
                       'do_disable_monitor_mode', 'set_channel', 'print_default_config', 'mac_lookup']

    config_from_args = vars(args)
    config_from_args = {k: v for k, v in config_from_args.items()
                        if v is not None and k not in non_config_args}

    # Config from args trumps everything
    config.update(config_from_args)

    config['devices_to_watch'] = macs_from_config + macs_from_args
    config['aps_to_watch'] = aps_from_config + aps_from_args
    if args.channels_to_monitor:
        channels_to_monitor = args.channels_to_monitor.split(',')
        config['channels_to_monitor'] = channels_to_monitor

    if config['log_level'] == 'DEBUG':
        print('Config:')
        pprint.pprint(config)

    return config


def main():
    config = get_config()
    tj = TrackerJacker(**config)

    try:
        tj.start()
    except KeyboardInterrupt:
        print('Stopping...')
    finally:
        tj.stop()

if __name__ == '__main__':
    main()
