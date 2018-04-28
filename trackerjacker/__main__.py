#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413

import os
import sys
import time
import json
import errno
import pprint
import logging
import inspect
import traceback

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy

from . import config_management
from . import device_management
from . import dot11_frame
from . import dot11_mapper
from . import dot11_tracker
from . import plugin_parser
from . import ieee_mac_vendor_db
from .common import TJException

LOG_NAME_TO_LEVEL = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}


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
    log_level = LOG_NAME_TO_LEVEL.get(log_level_str.upper(), 20)
    logger.setLevel(log_level)
    return logger


class TrackerJacker:
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
                 do_track=False,
                 threshold=None,
                 power=None,
                 devices_to_watch=(),
                 aps_to_watch=(),
                 threshold_window=10,
                 trigger_plugin=None,
                 plugin_config=None,
                 trigger_command=None,
                 trigger_cooldown=30,
                 beep_on_trigger=False):  # seconds

        self.iface = iface
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

        self.dot11_map.window = threshold_window

        if channel_switch_scheme == 'default':
            if self.do_map:
                channel_switch_scheme = 'round_robin'
            else:  # track mode
                channel_switch_scheme = 'traffic_based'

        self.devices_to_watch_set = set([dev['mac'].lower() for dev in devices_to_watch if 'mac' in dev])
        self.aps_to_watch_set = set([ap['bssid'].lower() for ap in aps_to_watch if 'bssid' in ap])

        if self.do_track:
            # Build trigger hit function
            if trigger_plugin:
                trigger_plugin = config_management.get_real_plugin_path(trigger_plugin)
                parsed_trigger_plugin = plugin_parser.parse_trigger_plugin(trigger_plugin, plugin_config)
            else:
                parsed_trigger_plugin = None

            self.dot11_tracker = dot11_tracker.Dot11Tracker(self.logger,
                                                            threshold,
                                                            power,
                                                            devices_to_watch,
                                                            aps_to_watch,
                                                            parsed_trigger_plugin,
                                                            trigger_command,
                                                            trigger_cooldown,
                                                            threshold_window,
                                                            beep_on_trigger,
                                                            self.dot11_map)

        self.iface_manager = device_management.Dot11InterfaceManager(iface,
                                                                     self.logger,
                                                                     channels_to_monitor,
                                                                     channel_switch_scheme,
                                                                     time_per_channel)

    def process_packet(self, pkt):
        if pkt.haslayer(scapy.Dot11):
            looking_for_specifics_and_none_found = self.aps_to_watch_set or self.devices_to_watch_set
            frame = dot11_frame.Dot11Frame(pkt, int(self.iface_manager.current_channel), iface=self.iface_manager.iface)
            if self.do_map:
                self.log_newly_found(frame)

            if self.display_all_packets:
                print('\t', pkt.summary())

            # See if any APs we care about (if we're looking for specific APs)
            if self.aps_to_watch_set:
                if frame.bssid not in self.aps_to_watch_set:
                    looking_for_specifics_and_none_found = False

            # See if any MACs we care about (if we're looking for specific MACs)
            if self.devices_to_watch_set:
                matched_macs = self.devices_to_watch_set & frame.macs
                if matched_macs:
                    looking_for_specifics_and_none_found = False

                    # Display matched packets (if specified)
                    if self.display_matching_packets and not self.display_all_packets:
                        print('\t', pkt.summary())

            # If we are looking for specific APs or Devices and none are found, no further processing needed
            if looking_for_specifics_and_none_found:
                return

            # If map mode enabled, do it. Note that we don't exclude non-matching MACs from the mapping
            # (which is why this isn't under the 'if matched_matcs' block).
            # Note: we update the map whether do_map is true or false since it's used for tracking; just don't save map
            self.dot11_map.add_frame(frame)
            if self.do_map:
                if time.time() - self.map_last_save >= self.map_save_interval:
                    self.dot11_map.save_to_file(self.map_file)
                    self.map_last_save = time.time()

            if self.do_track:
                self.dot11_tracker.add_frame(frame, pkt)

            # Update device tracking (for traffic-based)
            self.iface_manager.add_frame(frame)

    def log_newly_found(self, frame):
        # Log newly-found things
        if frame.ssid and frame.bssid not in self.dot11_map.access_points.keys():
            self.logger.info('SSID found: %s, BSSID: %s, Channel: %d', frame.ssid, frame.bssid, frame.channel)

        new_macs = [mac for mac in frame.macs
                    if mac not in (self.dot11_map.devices.keys() |
                                   self.dot11_map.access_points.keys() |
                                   dot11_mapper.MACS_TO_IGNORE)]
        for mac in new_macs:
            if mac:  # The frame can be crafted to include a null mac
                self.logger.info('MAC found: %s, Channel: %d', mac, frame.channel)

    def start(self):
        self.logger.debug('Starting monitoring on %s', self.iface_manager.iface)
        self.iface_manager.start()
        while True:
            try:
                if 'exceptions' in inspect.signature(scapy.sniff).parameters:
                    scapy.sniff(iface=self.iface_manager.iface, prn=self.process_packet, store=0, exceptions=True)
                    break
                else:
                    # For versions of scapy that don't provide the exceptions kwarg
                    scapy.sniff(iface=self.iface_manager.iface, prn=self.process_packet, store=0)
                    break
            except (IOError, OSError):
                self.logger.error(traceback.format_exc())
                self.logger.info('Sniffer error occurred. Restarting sniffer in 3 seconds...')
                time.sleep(3)

    def stop(self):
        self.iface_manager.stop()

        if self.do_map:
            # Flush map to disk
            self.dot11_map.save_to_file(self.map_file)


def do_simple_tasks_if_specified(args):
    if args.version:
        from .version import __version__
        print('trackerjacker {}'.format(__version__))
        sys.exit(0)
    elif args.do_enable_monitor_mode:
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
        print(json.dumps(config_management.DEFAULT_CONFIG, indent=4, sort_keys=True))
        sys.exit(0)
    elif args.set_channel:
        if not args.iface:
            raise TJException('You must specify the interface with the -i paramter')
        channel = args.set_channel[0]
        device_management.switch_to_channel(args.iface, channel)
        print('Set channel to {} on {}'.format(channel, args.iface))
        sys.exit(0)


def main():
    if not os.getuid() == 0:
        print('trackerjacker requires r00t!', file=sys.stderr)
        sys.exit(errno.EPERM)

    argparse_args = config_management.get_arg_parser().parse_args()

    # Some command-line args specify to just perform a simple task and then exit
    try:
        do_simple_tasks_if_specified(argparse_args)
    except TJException as e:
        print('Error: {}'.format(e), file=sys.stderr)
        sys.exit(1)

    try:
        config = config_management.build_config(argparse_args)
    except TJException as e:
        print('{}'.format(e))
        sys.exit(1)

    if config['log_level'] == 'DEBUG':
        print('Config:')
        pprint.pprint(config)

    # Setup logger
    logger = make_logger(config.pop('log_path'), config.pop('log_level'))

    try:
        tj = TrackerJacker(**dict(config, **{'logger': logger}))  # pylint: disable=E1123
        tj.start()
    except TJException as e:
        logger.critical('Error: %s', e)
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
