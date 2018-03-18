#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413

import copy
import json
import argparse

from .common import TJException

# Default config
DEFAULT_CONFIG = {'log_path': None,
                  'log_level': 'INFO',
                  'iface': None,
                  'devices_to_watch': [],
                  'aps_to_watch': [],
                  'threshold': None,
                  'power': None,
                  'threshold_window': 10,
                  'do_map': True,
                  'do_track': False,
                  'map_file': 'wifi_map.yaml',
                  'map_save_interval': 10,
                  'trigger_command': None,
                  'trigger_cooldown': 30,
                  'eval_interval': 1,  # seconds
                  'channels_to_monitor': None,
                  'channel_switch_scheme': 'default',
                  'time_per_channel': 2,
                  'display_matching_packets': False,
                  'display_all_packets': False}


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
    parser.add_argument('--threshold', type=int, dest='threshold',
                        help='Default data threshold (unless overridden on a per-dev basis) for triggering')
    parser.add_argument('--power', type=int, dest='power',
                        help='Default power threshold (unless overridden on a per-dev basis) for triggering')
    parser.add_argument('--trigger-command', type=str, dest='trigger_command',
                        help='Command to execute upon alert')
    parser.add_argument('--trigger-cooldown', type=str, dest='trigger_cooldown',
                        help='Time in seconds between trigger executions for a particular device')
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


def parse_command_line_watch_list(watch_str):
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
        * 11:22:33:44:55:66=-30
            - This means trigger if 11:22:33:44:55:66 is seen at a power level >= -30dBm (negative value implies power)

    Returns dict in this format:
        {'aa:bb:cc:dd:ee:ff': {'threshold': 100, 'power': None},
         '11:22:33:44:55:66': {'threshold': None, 'power': -30}}
    """

    watch_list = [i.strip() for i in watch_str.split(',')]
    watch_dict = {}

    for watch_part in watch_list:
        power = None
        threshold = None

        if '=' in watch_part:
            # dev_id is a MAC, BSSID, or SSID
            dev_id, val = [i.strip() for i in watch_part.split('=')]
            try:
                val = int(val)
            except ValueError:
                # Can't parse with "dev_id=threshold" formula, so assume '=' sign was part of ssid
                dev_id = watch_part

            if val > 0:
                threshold = val
            else:
                power = val
        else:
            dev_id = watch_part

        watch_dict[dev_id] = {'threshold': threshold, 'power': power}

    return watch_dict


def determine_watch_list(to_watch_from_args,
                         to_watch_from_config,
                         generic_threshold,
                         generic_power,
                         generic_trigger_command,
                         generic_trigger_cooldown):
    """ Coalesces the to_watch list from the command-line arguments, the config file,
    and the the general threshold, power, and trigger command. The main idea here is to look
    for the config values set on a per-device basis, and prioritize those, but if they are not there,
    fall back to the "generic_*" version. And if those have not been specified, fall back to defaults.

    Example input:
        to_watch_from_args = 'aa:bb:cc:dd:ee:ff=1337, 11:22:33:44:55:66=100, ff:ee:dd:cc:bb:aa',
        to_watch_from_config = {}
        generic_threshold = 1337
        generic_power = None
        generic_trigger_commmand = './alert.sh'
        gneric_trigger_cooldown = 60

    Returns a dict in this format:
        {
            'aa:bb:cc:dd:ee:ff': {
                'threshold': None,
                'power': -40,
                'trigger_command': './alert.sh',
                'trigger_cooldown': 60
            },
            '11:22:33:44:55:66': {
                'threshold': 100,
                'power': None,
                'trigger_command': './alert.sh',
                'trigger_cooldown': 60
            },
            'ff:ee:dd:cc:bb:aa': {
                'threshold': 1337,
                'power': None,
                'trigger_command': './alert.sh',
                'trigger_cooldown': 60
            }
        }
    """

    # Converts from cli param format like: "aa:bb:cc:dd:ee:ff=-40,11:22:33:44:55:66=100' to a map like:
    #   {'aa:bb:cc:dd:ee:ff': {'threshold': None, 'power': -40},
    #    '11:22:33:44:55:66': {'threshold': 100, 'power': None}
    if to_watch_from_args:
        to_watch_from_args = parse_command_line_watch_list(to_watch_from_args)

    if not to_watch_from_args:
        to_watch_from_args = {}
    if not to_watch_from_config:
        to_watch_from_config = {}

    watch_config_dict = {}
    for dev_id in to_watch_from_args.keys() | to_watch_from_config.keys():
        trigger_command = to_watch_from_config.get(dev_id, {}).get('trigger_command', None) or generic_trigger_command
        trigger_cooldown = to_watch_from_config.get(dev_id, {}).get('trigger_cooldown', None) or \
                           generic_trigger_cooldown or DEFAULT_CONFIG['trigger_cooldown']

        # Make sure data types are right
        try:
            trigger_cooldown = int(trigger_cooldown)
        except (TypeError, ValueError):
            trigger_cooldown = 0

        watch_entry = {'threshold': None,
                       'power': None,
                       'trigger_command': trigger_command,
                       'trigger_cooldown': trigger_cooldown}
        watch_entry['threshold'] = (to_watch_from_args.get(dev_id, {}).get('threshold', None) or
                                    to_watch_from_config.get(dev_id, {}).get('threshold', None))
        watch_entry['power'] = (to_watch_from_args.get(dev_id, {}).get('power', None) or
                                to_watch_from_config.get(dev_id, {}).get('power', None))

        if not watch_entry['threshold'] and not watch_entry['power']:
            if generic_threshold and not generic_power:
                watch_entry['threshold'] = generic_threshold
            elif generic_power:
                watch_entry['power'] = generic_power
            else:
                watch_entry['threshold'] = 1

        watch_config_dict[dev_id] = watch_entry

    return watch_config_dict


def build_config(args):
    config = copy.deepcopy(DEFAULT_CONFIG)
    devices_from_config = {}
    aps_from_config = {}
    generic_threshold_from_config = None
    generic_power_from_config = None
    generic_trigger_command_from_config = None
    generic_trigger_cooldown_from_config = None

    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_from_file = json.loads(f.read())

            # If there are any keys defined in the config file not allowed, error out
            invalid_keys = set(config_from_file.keys()) - set(config.keys())
            if invalid_keys:
                raise TJException('Invalid keys found in config file: {}'.format(invalid_keys))

            devices_from_config = config_from_file.pop('devices_to_watch', {})
            aps_from_config = config_from_file.pop('aps_to_watch', {})
            generic_threshold_from_config = config_from_file.pop('threshold', None)
            generic_power_from_config = config_from_file.pop('power', None)
            generic_trigger_command_from_config = config_from_file.pop('trigger_command', None)
            generic_trigger_cooldown_from_config = config_from_file.pop('trigger_cooldown', None)

            config.update(config_from_file)
            print('Loaded configuration from {}'.format(args.config))

        except (IOError, OSError, json.decoder.JSONDecodeError) as e:
            raise TJException('Error loading config file ({}): {}'.format(args.config, e))

    non_config_args = {'config', 'devices_to_watch', 'aps_to_watch', 'do_enable_monitor_mode',
                       'do_disable_monitor_mode', 'set_channel', 'print_default_config', 'mac_lookup',
                       'threshold', 'power', 'trigger_command'}

    config_from_args = vars(args)
    config_from_args = {k: v for k, v in config_from_args.items()
                        if v is not None and k not in non_config_args}

    # Config from args trumps everything
    config.update(config_from_args)

    # Remove intermediary config items from config
    for interim_config in {'threshold', 'power', 'trigger_command', 'trigger_cooldown'}:
        config.pop(interim_config, None)

    # Only allow track or map mode at once
    if config['do_track']:
        config['do_map'] = False
    if not config['do_track']:
        config['do_map'] = True

    generic_threshold = args.threshold or generic_threshold_from_config
    generic_power = args.power or generic_power_from_config
    generic_trigger_command = args.trigger_command or generic_trigger_command_from_config
    generic_trigger_cooldown = args.trigger_cooldown or generic_trigger_cooldown_from_config

    # If we're in track mode and no other threshold info is set, default to a 1 byte data threshold
    if config['do_track']:
        if not generic_threshold and not generic_power:
            generic_threshold = 1

        config['devices_to_watch'] = determine_watch_list(args.devices_to_watch,
                                                          devices_from_config,
                                                          generic_threshold,
                                                          generic_power,
                                                          generic_trigger_command,
                                                          generic_trigger_cooldown)

        config['aps_to_watch'] = determine_watch_list(args.aps_to_watch,
                                                      aps_from_config,
                                                      generic_threshold,
                                                      generic_power,
                                                      generic_trigger_command,
                                                      generic_trigger_cooldown)

    if args.channels_to_monitor:
        channels_to_monitor = args.channels_to_monitor.split(',')
        config['channels_to_monitor'] = channels_to_monitor

    return config
