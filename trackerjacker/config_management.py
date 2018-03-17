#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413

import json
import argparse

from .common import TJException

# Default config
DEFAULT_CONFIG = {'log_path': None,
                  'log_level': 'INFO',
                  'iface': None,
                  'devices_to_watch': [],
                  'aps_to_watch': [],
                  'threshold_window': 10,
                  'do_map': True,
                  'do_track': False,
                  'map_file': 'wifi_map.yaml',
                  'map_save_interval': 10,
                  'alert_cooldown': 30,
                  'alert_command': None,
                  'channels_to_monitor': None,
                  'channel_switch_scheme': 'round_robin',
                  'time_per_channel': 2,
                  'display_matching_packets': False,
                  'display_all_packets': False}


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

            macs_from_config = config_from_file.pop('devices_to_watch', {})
            aps_from_config = config_from_file.pop('aps_to_watch', {})

            config.update(config_from_file)
            print('Loaded configuration from {}'.format(args.config))

        except (IOError, OSError, json.decoder.JSONDecodeError) as e:
            raise TJException('Error loading config file ({}): {}'.format(args.config, e))

    macs_from_args = {}
    aps_from_args = {}

    # Converts from cli param format like: "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66' to a map like
    #   {'aa:bb:cc:dd:ee:ff': 1, '11:22:33:44:55:66': 1}
    if args.devices_to_watch:
        macs_from_args = parse_watch_list(args.devices_to_watch)

    # Converts from cli param format like "my_ssid1=5000,bssid2=1337" to a map like:
    #   {'my_ssid1': 5000, 'bssid2': 1337}
    if args.aps_to_watch:
        aps_from_args = parse_watch_list(args.aps_to_watch)

    non_config_args = ['config', 'devices_to_watch', 'aps_to_watch', 'do_enable_monitor_mode',
                       'do_disable_monitor_mode', 'set_channel', 'print_default_config', 'mac_lookup']

    config_from_args = vars(args)
    config_from_args = {k: v for k, v in config_from_args.items()
                        if v is not None and k not in non_config_args}

    # Config from args trumps everything
    config.update(config_from_args)

    # Only allow track or map mode at once
    if config['do_track']:
        config['do_map'] = False
    if not config['do_track']:
        config['do_map'] = True

    config['devices_to_watch'] = dict(macs_from_config, **macs_from_args)
    config['aps_to_watch'] = dict(aps_from_config, **aps_from_args)

    if args.channels_to_monitor:
        channels_to_monitor = args.channels_to_monitor.split(',')
        config['channels_to_monitor'] = channels_to_monitor

    return config


def parse_watch_list(watch_str):
    """ Parse string to represent devices to watch config

    Valid examples:
        * aa:bb:cc:dd:ee:ff
            - Threshold of 1 for the given MAC address
        * aa:bb:cc:dd:ee:ff,11:22:33:44:55:66
            - This means look for any traffic from either address
        * aa:bb:cc:dd:ee:ff=1337, 11:22:33:44:55:66=1000
            - This means look for 1337 bytes for the first address, and 1000 for the second
        * my_ssid, 11:22:33:44:55:66=1000
            - This means look for 1 byte from my_ssid or 1000 for the second

    Returns dict in this format:
        {'aa:bb:cc:dd:ee:ff': threshold1, '11:22:33:44:55:66': threshold2}
    """

    watch_list = [i.strip() for i in watch_str.split(',')]
    watch_dict = {}

    for watch_part in watch_list:
        if '=' in watch_part:
            # dev_id is a MAC, BSSID, or SSID
            dev_id, threshold = [i.strip() for i in watch_part.split('=')]
            try:
                threshold = int(threshold)
            except ValueError:
                # Can't parse with "dev_id=threshold" formula, so assume '=' sign was part of ssid
                dev_id = watch_part
                threshold = 1

            watch_part.split('=')
        else:
            # Can't parse with "dev_id=threshold" formula, so assume...
            dev_id = watch_part
            threshold = 1

        watch_dict[dev_id] = threshold
    return watch_dict


def get_arg_parser():
    """ Returns the configured argparse object. """
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
    parser.add_argument('-w', '--time-window', type=int, dest='threshold_window',
                        help='Time window (in seconds) which alert threshold is applied to')
    parser.add_argument('--map-save-interval', type=float, dest='map_save_interval',
                        help='Number of seconds between saving the wifi map to disk')
    parser.add_argument('--eval_interval', type=float, dest='eval_interval',
                        help='Number of seconds between looking for tracked devices')
    parser.add_argument('--power', action='store_true', dest='threshold_is_power',
                        help='If specified, all tracking thresholds are taken to represent RSSI power levels')
    parser.add_argument('--alert-command', type=str, dest='alert_command',
                        help='Command to execute upon alert')
    parser.add_argument('--display-all-packets', action='store_true', dest='display_all_packets',
                        help='If true, displays all packets matching filters')
    parser.add_argument('--map-file', type=str, dest='map_file', default='wifi_map.yaml',
                        help='File path to which to output wifi map; default: wifi_map.yaml')
    parser.add_argument('--log-path', type=str, dest='log_path', default=None,
                        help='Log path; default is stdout')
    parser.add_argument('--log-level', type=str, dest='log_level', default='INFO',
                        help='Log level; Options: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    parser.add_argument('-c', '--config', type=str, dest='config',
                        help='Path to config json file; For example config file, use --print-default-config')

    return parser
