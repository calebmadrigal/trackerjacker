#!/usr/bin/env python3

"""
tracker-jacker

Raw 802.11 frame interception tool.
"""

import os
import re
import time
import itertools
import threading
import datetime
import json
import argparse
from scapy.all import *

__author__ = "Caleb Madrigal"
__maintainer__ = "Caleb Madrigal"
__email__ = "caleb.adrigal@gmail.com"
__license__ = "MIT"
__version__ = "0.0.1"


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


class TrackerJacker:
    def __init__(self, iface='wlan0',
                       devices_to_watch=(),
                       aps_to_watch=(),
                       window_secs=10,
                       alert_threshold=1,
                       alert_cooldown=30,
                       alert_new_macs=True,
                       alert_new_ssids=True,
                       alert_command=None,
                       log_file='tracker_jacker.log',
                       ssid_log_file='ssids.txt',
                       mac_log_file='macs_seen.txt',
                       channels_to_monitor=None,
                       channel_switch_scheme='traffic_based',
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

        # Convert devices_to_watch and aps_to_watch into more efficient/usable data structures
        # Note that scapy represents MACs in lowercase
        def lowercase_macs(config_dict):
            if 'mac' in config_dict:
                config_dict['mac'] = config_dict['mac'].lower()
            elif 'bssid' in config_dict:
                config_dict['bssid'] = config_dict['bssid'].lower()
            return config_dict

        self.devices_to_watch = {dev.pop('mac').lower(): dev for dev in devices_to_watch if 'mac' in dev}
        self.devices_to_watch_set = set([mac for mac in self.devices_to_watch.keys()])

        self.aps_to_watch = {ap.pop('bssid').lower(): ap for ap in aps_to_watch if 'bssid' in ap}
        self.aps_to_watch_set = set([bssid for bssid in self.aps_to_watch.keys()])
        self.aps_ssids_to_watch_set = set([ap['ssid'] for ap in aps_to_watch if 'ssid' in ap])

        self.window_secs = window_secs
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

        self.switch_to_channel(self.current_channel)

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

    def switch_to_channel(self, channel_num):
        print('Switching to channel {}'.format(channel_num))
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

        self.do_alert(beeps=1)

    def new_ssid_found(self, ssid):
        print('A new SSID found: {}'.format(ssid))

        with open(self.ssid_log_file, 'a') as f:
            f.write('channel={}, ssid={}\n'.format(self.current_channel, ssid))

        self.do_alert(beeps=1)

    def process_packet(self, pkt):
        if pkt.haslayer(Dot11):
            if self.display_all_packets:
                print('\t', pkt.summary())

            macs_in_pkt = set([pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3, pkt[Dot11].addr4])
            self.num_msgs_received_this_channel += 1

            if self.alert_new_macs:
                self.check_for_unseen_macs(macs_in_pkt)

            if self.alert_new_ssids:
                self.check_for_unseen_ssids(pkt)

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
            subprocess.call(self.alert_command, shell=True)

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
              'alert_threshold': 1,
              'alert_cooldown': 30,
              'alert_new_macs': True,
              'alert_new_ssids': True,
              'alert_command': None,
              'log_file': 'tracker_jacker.log',
              'ssid_log_file': 'ssids_seen.txt',
              'mac_log_file': 'macs_seen.txt',
              'channels_to_monitor': None,
              'channel_switch_scheme': 'traffic_based',
              'time_per_channel': 2,
              'display_matching_packets': True,
              'display_all_packets': False,
             }

    default_config_str = ', '.join(['{} = {}'.format(k, v) for k, v in config.items()])

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, dest='iface',
                        help='Network interface to use')
    parser.add_argument('-m', '--macs', type=str, dest='devices_to_watch',
                        help='MAC(s) to track; comma separated for multiple')
    parser.add_argument('-a', '--access-points', type=str, dest='aps_to_watch',
                        help='Access point(s) to track - specified by BSSID; comma separated for multiple')
    parser.add_argument('-t', '--threshold', type=int, dest='alert_threshold',
                        help='Threshold of packets in time window which causes alert')
    parser.add_argument('-w', '--time-window', type=int, dest='window_secs',
                        help='Time window (in seconds) which alert threshold is applied to')
    parser.add_argument('--alert-command', type=str, dest='alert_command',
                        help='Command to execute upon alert')
    parser.add_argument('--monitor-mode-on', action='store_true', dest='enable_monitor_mode',
                        help='Enables monitor mode on the specified interface')
    parser.add_argument('--monitor-mode-off', action='store_true', dest='disable_monitor_mode',
                        help='Disables monitor mode on the specified interface')
    parser.add_argument('--set-channel', metavar='CHANNEL', dest='set_channel', nargs=1,
                        help='Set the specified wireless interface to the specified channel')
    parser.add_argument('-c', '--config', type=str, dest='config',
                        help='Path to config json file; default config values: \n' + default_config_str)

    # vars converts from namespace to dict
    args = parser.parse_args()

    if args.enable_monitor_mode:
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
    elif args.disable_monitor_mode:
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
        
    
    macs_from_config = []
    aps_from_config = []

    if args.config:
        try:
            with open(args.config) as f:
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

        except (FileNotFoundException, IOError, OSError) as e:
            print('Error loading config file ({}): {}'.format(args.config, e))
            sys.exit(1)

    macs_from_args = []
    aps_from_args = []

    if args.devices_to_watch:
        macs_from_args = [{'mac': mac} for mac in args.devices_to_watch.split(',')]
    if args.aps_to_watch:
        macs_from_args = [{'bssid': bssid} for bssid in args.aps_to_watch.split(',')]

    config_from_args = vars(args)
    config_from_args = {k:v for k,v in config_from_args.items()
                        if v is not None and k not in ['config', 'devices_to_watch', 'aps_to_watch']}

    # Config from args trumps everything
    config.update(config_from_args)

    config['devices_to_watch'] = macs_from_config + macs_from_args
    config['aps_to_watch'] = aps_from_config + aps_from_args

    import pprint
    print('Config:')
    pprint.pprint(config)

    return config

if __name__ == '__main__':
    config = get_config()
    tracker_jacker = TrackerJacker(**config)

    try:
        tracker_jacker.start()
    except KeyboardInterrupt:
        print('Stopping...')
    finally:
        tracker_jacker.stop()

