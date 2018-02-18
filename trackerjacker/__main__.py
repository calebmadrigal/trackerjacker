#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413

import os
import sys
import time
import json
import errno
import random
import pprint
import logging
import argparse
import threading
from contextlib import contextmanager

from . import device_management
from . import dot11_frame
from . import dot11_mapper
from . import dot11_tracker
from . import ieee_mac_vendor_db
from .common import TJException

# Default config
DEFAULT_CONFIG = {'log_path': None,
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


def is_admin():
    return os.getuid() == 0


class TrackerJacker:
    # pylint: disable=R0902
    def __init__(self,
                 logger=None,
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
        self.mac_vendor_db = ieee_mac_vendor_db.MacVendorDB()

        self.last_channel_switch_time = 0
        self.num_msgs_received_this_channel = 0
        self.current_channel = 1
        self.stop_event = threading.Event()

        if logger:
            self.logger = logger
        else:
            self.logger = make_logger()

        # Throws TJException if it fails to find suitable interface
        self.iface, self.need_to_disable_monitor_mode_on_exit = device_management.select_interface(iface, self.logger)

        # Throws TJException on failure
        self.configure_channels(channels_to_monitor, channel_switch_scheme)

        self.devices_to_watch_set = set([dev['mac'].lower() for dev in devices_to_watch if 'mac' in dev])
        self.aps_to_watch_set = set([ap['bssid'].lower() for ap in aps_to_watch if 'bssid' in ap])

        if self.do_map:
            self.logger.info('Map output file: %s', self.map_file)
            self.dot11_map = dot11_mapper.Dot11Mapper(self.logger)
            if os.path.exists(self.map_file):
                self.dot11_map.load_from_file(self.map_file)
            self.map_last_save = time.time()

        if self.do_track:
            self.dot11_tracker = dot11_tracker.Dot11Tracker(self.logger, devices_to_watch, aps_to_watch,
                                                            threshold_bytes, threshold_window, alert_cooldown,
                                                            alert_command)

    def configure_channels(self, channels_to_monitor, channel_switch_scheme):
        # Find supported channels
        self.supported_channels = device_management.get_supported_channels(self.iface)
        if not self.supported_channels:
            raise TJException('Interface either not found, or incompatible: {}'.format(self.iface))

        if channels_to_monitor:
            channels_to_monitor_set = set([int(c) for c in channels_to_monitor])
            if len(channels_to_monitor_set & set(self.supported_channels)) != len(channels_to_monitor_set):
                raise TJException('Not all of channels to monitor are supported by {}'.format(self.iface))

            self.channels_to_monitor = channels_to_monitor
            self.current_channel = self.channels_to_monitor[0]
            self.logger.info('Monitoring channels: %s', channels_to_monitor_set)
        else:
            self.channels_to_monitor = self.supported_channels
            self.current_channel = self.supported_channels[0]
            self.logger.info('Monitoring all available channels on %s: %s', self.iface, self.supported_channels)

        if channel_switch_scheme == 'default':
            if self.do_map:
                channel_switch_scheme = 'round_robin'
            else:
                channel_switch_scheme = 'traffic_based'

        self.logger.debug('Channel switching scheme: %s', channel_switch_scheme)

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

    def channel_switcher_thread(self, firethread=True):  # pylint: disable=R1710
        if firethread:
            t = threading.Thread(target=self.channel_switcher_thread, args=(False,))
            t.daemon = True
            t.start()
            return t

        # Only worry about switching channels if we are monitoring 2 or more
        if len(self.channels_to_monitor) > 1:
            while not self.stop_event.is_set():
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
            frame = dot11_frame.Dot11Frame(pkt)
            self.num_msgs_received_this_channel += 1

            if self.display_all_packets:
                print('\t', pkt.summary())

            # Filter out packets not in the list of Access Points to monitor (if specified)
            if self.aps_to_watch_set:
                if frame.bssid not in self.aps_to_watch_set:
                    return

            # See if any MACs we care about are here
            matched_macs = self.devices_to_watch_set & frame.macs
            if matched_macs:
                # Display matched packets (if specified)
                if self.display_matching_packets and not self.display_all_packets:
                    print('\t', pkt.summary())

                # If Track mode enabled, do it. Note that tracking by "devices to watch" only
                # affects tracking, not mapping.
                if self.do_track:
                    num_bytes_in_pkt = len(pkt)
                    for mac in matched_macs:
                        self.dot11_tracker.add_bytes_for_mac(mac, num_bytes_in_pkt)

            # If map mode enabled, do it. Note that we don't exclude non-matching MACs from the mapping
            # (which is why this isn't under the 'if matched_matcs' block).
            if self.do_map:
                self.dot11_map.add_frame(int(self.current_channel), frame)
                if time.time() - self.map_last_save >= self.map_save_period:
                    self.dot11_map.save_to_file(self.map_file)
                    self.map_last_save = time.time()

    def start(self):
        self.logger.debug('Starting monitoring on %s', self.iface)

        if self.do_track:
            self.dot11_tracker.startTracking()

        scapy.sniff(iface=self.iface, prn=self.process_packet, store=0)

    def stop(self):
        self.stop_event.set()
        if self.need_to_disable_monitor_mode_on_exit:
            self.logger.info('\nDisabling monitor mode for interface: %s', self.iface)

            # Try to wait long enough for the channel switching thread to see the event so
            # the device isn't busy when we try to disable monitor mode.
            time.sleep(self.time_per_channel + 1)

            device_management.monitor_mode_off(self.iface)
            self.logger.debug('Disabled monitor mode for interface: %s', self.iface)

        if self.do_map:
            # Flush map to disk
            self.dot11_map.save_to_file(self.map_file)

        if self.do_track:
            self.dot11_tracker.stop()


def parse_command_line_args():
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
    return parser.parse_args()


def do_simple_tasks_if_specified(args):
    @contextmanager
    def handle_interface_not_found():
        if not args.iface:
            raise TJException('You must specify the interface with the -i paramter')
        try:
            yield
        except FileNotFoundError:
            raise TJException('Couldn\'t find requested interface: {}'.format(args.iface))

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
        vendor = ieee_mac_vendor_db.MacVendorDB().lookup(args.mac_lookup)
        if vendor:
            print(vendor)
        else:
            print('Vendor for {} not found'.format(args.mac_lookup), file=sys.stderr)
        sys.exit(0)
    elif args.print_default_config:
        print(json.dumps(DEFAULT_CONFIG, indent=4, sort_keys=True))
        sys.exit(0)
    elif args.set_channel:
        with handle_interface_not_found():
            channel = args.set_channel[0]
            device_management.switch_to_channel(args.iface, channel)
            print('Set channel to {} on {}'.format(channel, args.iface))
            sys.exit(0)


def build_config(args):
    config = DEFAULT_CONFIG

    macs_from_config = []
    aps_from_config = []

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_from_file = json.loads(f.read())

            # If there are any keys defined in the config file not allowed, error out
            invalid_keys = set(config_from_file.keys()) - set(config.keys())
            if invalid_keys:
                raise TJException('Invalid keys found in config file: {}'.format(invalid_keys))

            macs_from_config = [{'mac': dev} if isinstance(dev, str) else dev
                                for dev in config_from_file.pop('devices_to_watch', [])]
            aps_from_config = [{'bssid': ap} if isinstance(ap, str) else ap
                               for ap in config_from_file.pop('aps_to_watch', [])]

            config.update(config_from_file)
            print('Loaded configuration from {}'.format(args.config))

        except (IOError, OSError, json.decoder.JSONDecodeError) as e:
            raise TJException('Error loading config file ({}): {}'.format(args.config, e))

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
    if not is_admin():
        print('trackerjacker requires r00t!', file=sys.stderr)
        sys.exit(errno.EPERM)

    argparse_args = parse_command_line_args()

    # Some command-line args specify to just perform a simple task and then exit
    try:
        do_simple_tasks_if_specified(argparse_args)
    except TJException as e:
        print('Error: {}'.format(e), file=sys.stderr)

    config = build_config(argparse_args)

    # Setup logger
    logger = make_logger(config.pop('log_path'), config.pop('log_level'))

    try:
        tj = TrackerJacker(**config, logger=logger)  # pylint: disable=E1123
        tj.start()
    except TJException as e:
        logger.error('Error: %s', e)
    except KeyboardInterrupt:
        print('Stopping...')
    finally:
        try:
            tj.stop()
        except UnboundLocalError:
            # Exception was thrown in TrackerJacker initializer, so 'tj' doesn't exist
            pass

if __name__ == '__main__':
    main()
