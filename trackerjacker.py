#!/usr/bin/env python3

"""
trackerjacker

Raw 802.11 frame interception tool.
"""

import os
import re
import time
import itertools
import threading
import datetime
import json
import ast
import argparse
import pprint
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

__author__ = "Caleb Madrigal"
__email__ = "caleb.madrigal@gmail.com"
__license__ = "MIT"
__version__ = "0.0.4"


def get_physical_name(iface_name):
    physical_name= ''
    with open('/sys/class/net/{}/phy80211/index'.format(iface_name, 'r')) as f:
        physical_name = 'phy{}'.format(f.read().strip())
    return physical_name


def monitor_mode_on(iface):
    physical_name = get_physical_name(iface)
    mon_iface_name = '{}mon'.format(iface)
    subprocess.check_call('iw phy {} interface add {} type monitor'.format(physical_name, mon_iface_name), shell=True)
    subprocess.check_call('iw dev {} del'.format(iface), shell=True)
    subprocess.check_call('ifconfig {} up'.format(mon_iface_name), shell=True)
    return mon_iface_name


def monitor_mode_off(iface):
    # If someone passes in an interface like 'wlan0mon', assume it's the monitor name
    if 'mon' in iface:
        mon_iface_name = iface
        iface = iface.replace('mon', '')
    else:
        mon_iface_name = '{}mon'.format(iface)

    physical_name = get_physical_name(mon_iface_name)
    subprocess.check_call('iw phy {} interface add {} type managed'.format(physical_name, iface), shell=True)
    subprocess.check_call('iw dev {} del'.format(mon_iface_name), shell=True)
    return mon_iface_name


def find_mon_iface():
    """ Returns any interfaces with 'mon' in their name. """
    ifconfig_output = subprocess.check_output('ifconfig', shell=True).decode()
    lines = [line for line in ifconfig_output.split('\n')]
    for line in lines:
        match = re.match(r'(\w+):', line)
        if match:
            iface = match.groups()[0]
            if iface.find('mon') >= 0:
                return iface
    return None


def get_supported_channels(iface):
    iwlist_output = subprocess.check_output('iwlist {} freq'.format(iface), shell=True).decode()
    lines = [line.strip() for line in iwlist_output.split('\n')]
    channel_regex = re.compile(r'Channel\W+(\d+)')
    channels = []
    for line in lines:
        m = re.search(channel_regex, line)
        if m:
            c = m.groups()[0]
            channels.append(c)

    # '06' -> '6', and sort
    channels = [str(i) for i in sorted(list(set([int(chan) for chan in channels])))]
    return channels


def switch_to_channel(iface, channel_num):
    subprocess.call('iw dev {} set channel {}'.format(iface, channel_num), shell=True)


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

        if frame.haslayer(Dot11Elt) and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
            self.ssid = frame[Dot11Elt].info.decode().replace('\x00', '[NULL]')

    def is_management(self):
        return self.frame.type == 0

    def is_control(self):
        return self.frame.type == 1

    def is_data(self):
        return self.frame.type == 2

    def __str__(self):
        return 'Dot11 (type={}, from={}, to={}, bssid={}, ssid={})'.format(
               self.frame.type, self.src, self.dst, self.bssid, self.ssid)

    def __repr__(self):
        return self.__str__()


class Dot11Map:
    """ Builds/represents a map of this structure (and saves to yaml files):

    1:  # channel
      "90:35:ab:1c:25:19":  # bssid; Linksys
        ssid: "hacker"
        macs:
          - "00:03:7f:84:f8:09"  # Dropcam
          - "01:00:5e:00:00:fb"  # Apple
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Sony
          - "e8:50:8b:36:5e:bb"  # Unknown
    5:  # channel
      "34:89:ab:c4:15:69":  # bssid; 
        ssid: "hello-world"
        macs:
          - "b8:27:eb:d6:cc:e9"  # Samsung
          - "d8:49:2f:30:68:17"  # Apple
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Unknown
    """
    MACS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}

    def __init__(self):
        self.map_data = {}
        self.mac_vendor_db = MacVendorDB()
        self.associated_macs = set()
        self.bssid_to_ssid = {}

    def add_frame(self, channel, dot11_frame):
        if channel not in self.map_data:
            self.map_data[channel] = {'unassociated': {'ssid': None, 'macs': set()}}

        chan_to_bssid = self.map_data[channel]

        if dot11_frame.bssid and dot11_frame.bssid not in Dot11Map.MACS_TO_IGNORE:
            if dot11_frame.bssid not in chan_to_bssid:
                chan_to_bssid[dot11_frame.bssid] = {'ssid': None, 'macs': set()}
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

            # Now that each of these MACs have been associated with this bssid, they are no longer 'unassociated'
            self.associated_macs |= dot11_frame.macs
            self.delete_from_unassociated(dot11_frame.macs - Dot11Map.MACS_TO_IGNORE)
        else:
            bssid_node = chan_to_bssid['unassociated']
            bssid_node['macs'] |= dot11_frame.macs - Dot11Map.MACS_TO_IGNORE - self.associated_macs

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

            self.map_data = loaded_map
            return loaded_map

        except Exception as e:
            print('Error loading map from file ({}): {}'.format(file_path, e))
            return {}


class TrackerJacker:
    def __init__(self, iface='wlan0',
                       devices_to_watch=(),
                       aps_to_watch=(),
                       window_secs=10,
                       do_map=True,
                       map_file='wifi_map.yaml',
                       map_save_period=10,  # seconds
                       alert_threshold=1,
                       alert_cooldown=30,
                       alert_new_macs=True,
                       alert_new_ssids=True,
                       alert_command=None,
                       log_file='trackerjacker.log',
                       ssid_log_file='ssids.txt',
                       mac_log_file='macs_seen.txt',
                       channels_to_monitor=None,
                       channel_switch_scheme='round_robin',
                       time_per_channel=2,
                       display_matching_packets=True,
                       display_all_packets=False):

        # If 'mon' is in the interface name, assume it's already in interface mode
        # Otherwise, enable monitor mode and call monitor iface name iface + 'mon'
        # E.g. if iface is 'wlan0', create a monitor mode interface called 'wlan0mon'
        if 'mon' in iface:
            self.iface = iface
            self.original_iface_name = None
            print('Assuming iface is already in monitor mode...')
        else:
            try:
                self.iface = monitor_mode_on(iface)
                self.original_iface_name = iface
                print('Enabled monitor mode on {} as iface name: {}'.format(iface, self.iface))
            except Exception:
                # If we fail to find the specified (or default) interface, look to see if there is an
                # interface with 'mon' in the name, and if so, try it.
                print('Interface not found: {}; searching for valid monitor interface...'.format(iface))
                mon_iface = find_mon_iface()
                self.original_iface_name = None
                if mon_iface:
                    self.iface = mon_iface
                    print('Going with interface: {}'.format(self.iface))
                else:
                    print('Could not find monitor interface')
                    sys.exit(1)

        # Find supported channels
        self.supported_channels = get_supported_channels(self.iface)
        if len(self.supported_channels) == 0:
            print('Interface not found: {}'.format(self.iface))
            sys.exit(2)

        print('Supported channels: {}'.format(self.supported_channels))

        self.devices_to_watch = {dev.pop('mac').lower(): dev for dev in devices_to_watch if 'mac' in dev}
        self.devices_to_watch_set = set([mac for mac in self.devices_to_watch.keys()])

        self.aps_to_watch = {ap.pop('bssid').lower(): ap for ap in aps_to_watch if 'bssid' in ap}
        self.aps_to_watch_set = set([bssid for bssid in self.aps_to_watch.keys()])
        self.aps_ssids_to_watch_set = set([ap['ssid'] for ap in aps_to_watch if 'ssid' in ap])

        self.window_secs = window_secs
        self.do_map = do_map
        self.map_file = map_file
        self.map_save_period = map_save_period
        self.map_data = {}
        self.map_last_write_time = 0
        self.alert_threshold = alert_threshold
        self.alert_cooldown = alert_cooldown
        self.alert_new_macs = alert_new_macs
        self.alert_new_ssids = alert_new_ssids
        self.alert_command = alert_command
        self.log_file = log_file
        self.ssid_log_file= ssid_log_file
        self.mac_log_file = mac_log_file
        self.time_per_channel = time_per_channel
        self.display_matching_packets = display_matching_packets
        self.display_all_packets = display_all_packets
        self.mac_vendor_db = MacVendorDB()

        # If the mac log exists, assume each line in it is a MAC, and add it to the known MACs
        self.seen_macs = set()
        if os.path.exists(self.mac_log_file):
            try:
                with open(self.mac_log_file, 'r') as f:
                    seen_macs_list = []
                    for line in f.readlines():
                        mac_entry = ast.literal_eval(line)
                        seen_macs_list.append(mac_entry['mac'])
                    self.seen_macs = set(seen_macs_list)
                    print('Imported {} seen MACs'.format(len(self.seen_macs)))
            except Exception as e:
                print('Failed to import MACs from file: {}'.format(e))

        # If the SSID log exists, assume each line in it is an SSID, and add it to the known SSIDs
        self.seen_ssids = set()
        if os.path.exists(self.ssid_log_file):
            try:
                with open(self.ssid_log_file, 'r') as f:
                    ssids_seen_list = []
                    for line in f.readlines():
                        try:
                            ssid_entry = ast.literal_eval(line.strip())
                            ssids_seen_list.append(ssid_entry['ssid'])
                        except Exception:
                            pass
                    self.seen_ssids = set(ssids_seen_list)
                print('Imported {} seen SSIDs'.format(len(self.seen_ssids)))
                print(self.seen_ssids)
            except Exception as e:
                print('Failed to import SSIDs from file: {}'.format(e))

        # Mapping stuff
        if self.do_map:
            self.dot11_map = Dot11Map()
            if os.path.exists(self.map_file):
                self.dot11_map.load_from_file(self.map_file)
            self.map_last_save = time.time()

        self.packet_lens = {}
        self.packet_lens_lock = threading.Lock()
        self.last_alerted = {}
        self.last_channel_switch_time = 0

        if channels_to_monitor:
            self.channels_to_monitor = channels_to_monitor
            self.current_channel = self.channels_to_monitor[0]
        else:
            self.channels_to_monitor = self.supported_channels
            self.current_channel = self.supported_channels[0]

        self.channel_switch_func = self.switch_channel_based_on_traffic

        if channel_switch_scheme == 'traffic_based':
            self.channel_switch_func = self.switch_channel_based_on_traffic
        elif channel_switch_scheme == 'round_robin':
            self.channel_switch_func = self.switch_channel_round_robin

        # Start with a high count for each channel, so each channel is more likely to be tried
        # at least once before having the true count for it set
        self.msgs_per_channel = {c: 100000 for c in self.channels_to_monitor}
        self.num_msgs_received_this_channel = 0
        self.channel_switch_scheme = channel_switch_scheme

        self.switch_to_channel(self.current_channel, force=True)

        # Start channel switcher thread
        self.channel_switcher_thread()

    def get_threshold(self, mac):
        if mac in self.devices_to_watch and 'threshold' in self.devices_to_watch[mac]:
            return self.devices_to_watch[mac]['threshold']
        else:
            return self.alert_threshold

    def channel_switcher_thread(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.channel_switcher_thread, args=(False,))
            t.daemon = True
            t.start()
            return t

        # Only worry about switching channels if we are monitoring 2 or more
        if len(self.channels_to_monitor) > 1:
            while True:
                self.channel_switch_func()
                self.last_channel_switch_time = time.time()
                time.sleep(self.time_per_channel)

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
        print('Switching to channel {}'.format(channel_num))
        if channel_num == self.current_channel and not force:
            return
        switch_to_channel(self.iface, channel_num)
        self.current_channel = channel_num

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

    def check_for_unseen_macs(self, macs_in_pkt):
        unseen_macs = (macs_in_pkt - set([None])) - self.seen_macs
        for mac in unseen_macs:
            self.new_mac_found(mac)
            self.seen_macs |= set([mac])

    def new_mac_found(self, mac):
        print('A new MAC found: {}'.format(mac))

        with open(self.mac_log_file, 'a') as f:
            # Note: I'm manually building the dict str repr in order to have the same order on every line
            f.write("""{"mac": "%s", "vendor": "%s"}\n""" % (mac, self.mac_vendor_db.lookup(mac)))

        self.do_alert(beeps=1)

    def new_ssid_found(self, ssid, bssid):
        print('A new SSID: {}, BSSID: {}, Channel: {}'.format(ssid, bssid, self.current_channel))

        with open(self.ssid_log_file, 'a') as f:
            # Note: I'm manually building the dict str repr in order to have the same order on every line
            f.write("""{"ssid": "%s", "bssid": "%s", "channel": %d}\n""" % (ssid, bssid, int(self.current_channel)))

        self.do_alert(beeps=1)

    def process_packet(self, pkt):
        if pkt.haslayer(Dot11):
            dot11_frame = Dot11Frame(pkt)

            if self.display_all_packets:
                print(dot11_frame)

            macs_in_pkt = set([pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3, pkt[Dot11].addr4])
            self.num_msgs_received_this_channel += 1

            if self.do_map:
                self.dot11_map.add_frame(int(self.current_channel), dot11_frame)
                if time.time() - self.map_last_save >= self.map_save_period:
                    self.dot11_map.save_to_file(self.map_file)
                    self.map_last_save = time.time()

            if len(self.aps_to_watch) > 0:
                if dot11_frame.bssid in self.aps_to_watch_set:
                    print('Packet matching AP: {}'.format(pkt.summary()))
                else:
                    return

            if self.alert_new_macs:
                self.check_for_unseen_macs(macs_in_pkt)

            if self.alert_new_ssids:
                if dot11_frame.ssid and dot11_frame.ssid not in self.seen_ssids:
                    self.new_ssid_found(dot11_frame.ssid, dot11_frame.bssid)
                    self.seen_ssids |= set([dot11_frame.ssid])

            # See if any MACs we care about are here
            matched_macs = self.devices_to_watch_set & macs_in_pkt
            if matched_macs:
                if self.display_matching_packets and not self.display_all_packets:
                    print('\t', pkt.summary())

                with self.packet_lens_lock:
                    for mac in matched_macs:
                        packet_lens = self.get_packet_lens(mac)
                        packet_lens.append((time.time(), len(pkt)))

    def do_alert(self, beeps=5, thing_detected=None):
        if self.alert_command:
            # Start alert_command in background process - fire and forget
            subprocess.Popen(self.alert_command)

        for i in range(beeps):
            print(chr(0x07))
            time.sleep(0.2)

    def mac_of_interest_detected(self, mac):
        if time.time() - self.last_alerted.get(mac, 9999999) < self.alert_cooldown:
            return

        device_name = self.devices_to_watch[mac].get('name', mac)

        msg = '{}: Detected {}'.format(datetime.datetime.now(), device_name)
        print(msg)
        with open(self.log_file, 'a') as f:
            f.write(msg + '\n')

        self.do_alert()
        self.last_alerted[mac] = time.time()

    def check_loop(self):
        while True:
            for mac in self.devices_to_watch_set:
                bytes_received_in_time_window = self.get_bytes_in_time_window(mac)
                print('Bytes received in last {} seconds for {}: {}' \
                      .format(self.window_secs, mac, bytes_received_in_time_window))
                if bytes_received_in_time_window > self.get_threshold(mac):
                    self.mac_of_interest_detected(mac)

            time.sleep(5)

    def start(self):
        print('Starting monitoring on {}'.format(self.iface))
        t = threading.Thread(target=self.check_loop)
        t.daemon = True
        t.start()

        sniff(iface=self.iface, prn=self.process_packet, store=0)

    def stop(self):
        if self.original_iface_name:
            monitor_mode_off(self.iface)
            print('Disabled monitor mode for interface: {}'.format(self.original_iface_name))


def get_config():
    # Default config
    config = {'iface': 'wlan0',
              'devices_to_watch': [],
              'aps_to_watch': [],
              'window_secs': 10,
              'do_map': True,
              'map_file': 'wifi_map.yaml',
              'map_save_period': 10,
              'alert_threshold': 1,
              'alert_cooldown': 30,
              'alert_new_macs': True,
              'alert_new_ssids': True,
              'alert_command': None,
              'log_file': 'trackerjacker.log',
              'ssid_log_file': 'ssids_seen.txt',
              'mac_log_file': 'macs_seen.txt',
              'channels_to_monitor': None,
              'channel_switch_scheme': 'round_robin',
              'time_per_channel': 2,
              'display_matching_packets': True,
              'display_all_packets': False,
             }

    parser = argparse.ArgumentParser()
    # Modes
    parser.add_argument('--map', action='store_true', dest='do_map',
                        help='Map mode - output map to wifi_map.txt')
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
                        help='Network interface to use')
    parser.add_argument('-m', '--macs', type=str, dest='devices_to_watch',
                        help='MAC(s) to track; comma separated for multiple')
    parser.add_argument('-a', '--access-points', type=str, dest='aps_to_watch',
                        help='Access point(s) to track - specified by BSSID; comma separated for multiple')
    parser.add_argument('--channels-to-monitor', type=str, dest='channels_to_monitor',
                        help='Channels to monitor; comma separated for multiple')
    parser.add_argument('-t', '--threshold', type=int, dest='alert_threshold',
                        help='Threshold of packets in time window which causes alert')
    parser.add_argument('-w', '--time-window', type=int, dest='window_secs',
                        help='Time window (in seconds) which alert threshold is applied to')
    parser.add_argument('--alert-command', type=str, dest='alert_command',
                        help='Command to execute upon alert')
    parser.add_argument('--display-all-packets', action='store_true', dest='display_all_packets',
                        help='If true, displays all packets matching filters')
    parser.add_argument('-c', '--config', type=str, dest='config',
                        help='Path to config json file; For example config file, use --print-default-config')

    # vars converts from namespace to dict
    args = parser.parse_args()

    if args.do_enable_monitor_mode:
        if not args.iface:
            print('You must specify the interface with the -i paramter')
            sys.exit(1)
        try:
            result_iface = monitor_mode_on(args.iface)
            print('Enabled monitor mode on {} as iface name: {}'.format(args.iface, result_iface))
            sys.exit(0)
        except FileNotFoundError:
            print('Couldn\'t find requested interface: {}'.format(args.iface))
            sys.exit(1)
    elif args.do_disable_monitor_mode:
        if not args.iface:
            print('You must specify the interface with the -i paramter')
            sys.exit(1)
        try:
            result_iface = monitor_mode_off(args.iface)
            print('Disabled monitor mode on {}'.format(result_iface))
            sys.exit(0)
        except FileNotFoundError:
            print('Couldn\'t find requested interface: {}'.format(args.iface))
            sys.exit(1)
    elif args.mac_lookup:
        vendor = MacVendorDB().lookup(args.mac_lookup)
        if vendor:
            print(vendor)
        else:
            print('Vendor for {} not found'.format(args.mac_lookup))
        sys.exit(0)
    elif args.print_default_config:
        print(json.dumps(config, indent=4, sort_keys=True))
        sys.exit(0)
    elif args.set_channel:
        if not args.iface:
            print('You must specify the interface with the -i paramter')
            sys.exit(1)
        try:
            channel = args.set_channel[0]
            switch_to_channel(args.iface, channel)
            print('Set channel to {} on {}'.format(channel, args.iface))
            sys.exit(0)
        except FileNotFoundError:
            print('Couldn\'t find requested interface: {}'.format(args.iface))
            sys.exit(1)
    elif args.do_map:
        pass
        
    
    macs_from_config = []
    aps_from_config = []

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_from_file = json.loads(f.read())

            # If there are any keys defined in the config file not allowed, error out
            invalid_keys = set(config_from_file.keys()) - set(config.keys())
            if invalid_keys:
                print('Invalid keys found in config file: {}'.format(invalid_keys))
                sys.exit(1)

            macs_from_config = [{'mac': dev} if type(dev)==str else dev
                                for dev in config_from_file.pop('devices_to_watch', [])]
            aps_from_config = [{'bssid': ap} if type(ap)==str else ap
                                for ap in config_from_file.pop('aps_to_watch', [])]

            config.update(config_from_file)
            print('Loaded configuration from {}'.format(args.config))

        except (IOError, OSError, json.decoder.JSONDecodeError) as e:
            print('Error loading config file ({}): {}'.format(args.config, e))
            sys.exit(1)

    macs_from_args = []
    aps_from_args = []

    if args.devices_to_watch:
        macs_from_args = [{'mac': mac} for mac in args.devices_to_watch.split(',')]
    if args.aps_to_watch:
        macs_from_args = [{'bssid': bssid} for bssid in args.aps_to_watch.split(',')]

    non_config_args = ['config', 'devices_to_watch', 'aps_to_watch', 'do_enable_monitor_mode',
                       'do_disable_monitor_mode', 'set_channel', 'print_default_config', 'mac_lookup', 'do_map']

    config_from_args = vars(args)
    config_from_args = {k:v for k,v in config_from_args.items()
                        if v is not None and k not in non_config_args}

    # Config from args trumps everything
    config.update(config_from_args)

    config['devices_to_watch'] = macs_from_config + macs_from_args
    config['aps_to_watch'] = aps_from_config + aps_from_args
    if args.channels_to_monitor:
        channels_to_monitor = args.channels_to_monitor.split(',')
        config['channels_to_monitor'] = channels_to_monitor

    print('Config:')
    pprint.pprint(config)

    return config

if __name__ == '__main__':
    config = get_config()
    trackerjacker = TrackerJacker(**config)

    try:
        trackerjacker.start()
    except KeyboardInterrupt:
        print('Stopping...')
    finally:
        trackerjacker.stop()

