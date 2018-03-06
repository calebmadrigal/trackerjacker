#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413

import os
import sys
import time
import json
import errno
import pprint
import logging
import argparse

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
                  'map_save_interval': 10,
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
                 map_save_interval=10,  # seconds
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
        self.map_save_interval = map_save_interval
        self.display_matching_packets = display_matching_packets
        self.display_all_packets = display_all_packets
        self.mac_vendor_db = ieee_mac_vendor_db.MacVendorDB()

        if logger:
            self.logger = logger
        else:
            self.logger = make_logger()

        # Even if we are not in map mode, we still need to build the map for tracking purposes
        self.dot11_map = None
        if self.do_map:
            self.map_last_save = time.time()

            # Try to load map
            self.logger.info('Map output file: %s', self.map_file)
            if os.path.exists(self.map_file):
                self.dot11_map = dot11_mapper.Dot11Map.load_from_file(self.map_file)
            else:
                self.logger.warning('Specified map file not found - creating new map file.')

        if not self.dot11_map:
            self.dot11_map = dot11_mapper.Dot11Map()

        if channel_switch_scheme == 'default':
            if self.do_map:
                channel_switch_scheme = 'round_robin'
            else:
                channel_switch_scheme = 'traffic_based'

        self.iface_manager = device_management.Dot11InterfaceManager(iface,
                                                                     self.logger,
                                                                     channels_to_monitor,
                                                                     channel_switch_scheme,
                                                                     time_per_channel)

        self.devices_to_watch_set = set([dev['mac'].lower() for dev in devices_to_watch if 'mac' in dev])
        self.aps_to_watch_set = set([ap['bssid'].lower() for ap in aps_to_watch if 'bssid' in ap])

        if self.do_track:
            self.dot11_tracker = dot11_tracker.Dot11Tracker(self.logger, devices_to_watch, aps_to_watch,
                                                            threshold_bytes, threshold_window, alert_cooldown,
                                                            alert_command)

    def process_packet(self, pkt):
        if pkt.haslayer(scapy.Dot11):
            frame = dot11_frame.Dot11Frame(pkt, int(self.iface_manager.current_channel))
            self.log_newly_found(frame)

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
                self.dot11_map.add_frame(frame)
                if time.time() - self.map_last_save >= self.map_save_interval:
                    # dot11_mapper.save_map_to_file(self.map_file, self.dot11_map)
                    self.dot11_map.save_to_file(self.map_file)
                    self.map_last_save = time.time()

    def log_newly_found(self, frame):
        # Log newly-found things
        if frame.ssid and frame.bssid not in self.dot11_map.access_points.keys():
            self.logger.info('SSID found: %s, BSSID: %s, Channel: %d', frame.ssid, frame.bssid, frame.channel)

        new_macs = [mac for mac in frame.macs
                    if mac not in (self.dot11_map.devices.keys() |
                                   self.dot11_map.access_points.keys() |
                                   dot11_mapper.MACS_TO_IGNORE)]
        for mac in new_macs:
            self.logger.info('MAC found: %s, Channel: %d', mac, frame.channel)

    def start(self):
        self.logger.debug('Starting monitoring on %s', self.iface_manager.iface)

        self.iface_manager.start()

        if self.do_track:
            self.dot11_tracker.startTracking()

        scapy.sniff(iface=self.iface_manager.iface, prn=self.process_packet, store=0)

    def stop(self):
        self.iface_manager.stop()

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
    parser.add_argument('--map-save-interval', type=float, dest='map_save_interval',
                        help='Number of seconds between saving the wifi map to disk')
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
    if args.do_enable_monitor_mode:
        if not args.iface:
            raise TJException('You must specify the interface with the -i paramter')
        device_management.monitor_mode_on(args.iface)
        print('Enabled monitor mode on {}'.format(args.iface))
        sys.exit(0)
    elif args.do_disable_monitor_mode:
        if not args.iface:
            raise TJException('You must specify the interface with the -i paramter')
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
        if not args.iface:
            raise TJException('You must specify the interface with the -i paramter')
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
    if not os.getuid() == 0:
        print('trackerjacker requires r00t!', file=sys.stderr)
        sys.exit(errno.EPERM)

    argparse_args = parse_command_line_args()

    # Some command-line args specify to just perform a simple task and then exit
    try:
        do_simple_tasks_if_specified(argparse_args)
    except TJException as e:
        print('Error: {}'.format(e), file=sys.stderr)
        sys.exit(1)

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
