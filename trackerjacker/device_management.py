#!/usr/bin/env python3
# pylint: disable=C0111, C0103, C0413, W0703, R0902, R0903, R0912, R0913, R0914, R0915

import os
import re
import time
import random
import threading
import subprocess

from .common import TJException  # pylint: disable=E0401

ADAPTER_MODE_MANAGED = 1    # ARPHRD_ETHER
ADAPTER_MONITOR_MODE = 803  # ARPHRD_IEEE80211_RADIOTAP


def check_interface_exists(iface):
    if not os.path.exists('/sys/class/net/{}'.format(iface)):
        raise TJException('Interface {} not found'.format(iface))

def set_interface_mode(iface, mode):
    check_interface_exists(iface)
    subprocess.check_call('ifconfig {} down'.format(iface), shell=True)
    subprocess.check_call('iwconfig {} mode {}'.format(iface, mode), shell=True)
    subprocess.check_call('ifconfig {} up'.format(iface), shell=True)


def monitor_mode_on(iface):
    set_interface_mode(iface, 'monitor')


def monitor_mode_off(iface):
    set_interface_mode(iface, 'managed')


def get_network_interfaces():
    return os.listdir('/sys/class/net')


def is_monitor_mode_device(iface_name):
    check_interface_exists(iface_name)
    with open('/sys/class/net/{}/type'.format(iface_name), 'r') as f:
        adapter_mode = f.read().strip()

    try:
        adapter_mode = int(adapter_mode)
    except ValueError:
        return False

    return adapter_mode == ADAPTER_MONITOR_MODE


def find_monitor_interfaces():
    for iface_name in get_network_interfaces():
        try:
            if is_monitor_mode_device(iface_name):
                yield iface_name
        except TJException:
            # If there's any problem with any interface, keep looking
            pass


def find_first_monitor_interface():
    try:
        return next(find_monitor_interfaces())
    except StopIteration:
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

    # '07' -> 7, and sort
    channels = list(sorted(list(set([int(chan) for chan in channels]))))
    return channels

def switch_to_channel(iface, channel_num):
    subprocess.call('iw dev {} set channel {}'.format(iface, channel_num), shell=True)

def select_interface(iface, logger):
    selected_iface = None
    need_to_disable_monitor_mode_on_exit = False

    # If no device specified, see if there is a device already in monitor mode, and go with it...
    if not iface:
        monitor_mode_iface = find_first_monitor_interface()
        if monitor_mode_iface:
            selected_iface = monitor_mode_iface
            logger.info('Using monitor mode interface: %s', selected_iface)
        else:
            raise TJException('Please specify interface with -i switch')

    # If specified interface is already in monitor mode, do nothing... just go with it
    elif is_monitor_mode_device(iface):
        selected_iface = iface
        logger.debug('Interface %s is already in monitor mode...', iface)

    # Otherwise, try to put specified interface into monitor mode, but remember to undo that when done...
    else:
        try:
            logger.info('Enabling monitor mode on %s', iface)
            monitor_mode_on(iface)
            selected_iface = iface
            need_to_disable_monitor_mode_on_exit = True
            logger.debug('Enabled monitor mode on %s', iface)
        except Exception:
            # If we fail to find the specified (or default) interface, look to see if there is a monitor interface
            logger.warning('Could not enable monitor mode on enterface: %s', iface)
            mon_iface = find_first_monitor_interface()
            if mon_iface:
                selected_iface = mon_iface
                logger.info('Going with interface: %s', selected_iface)
            else:
                raise TJException('Could not find a monitor interface')

    return selected_iface, need_to_disable_monitor_mode_on_exit


class Dot11InterfaceManager:
    def __init__(self, iface, logger, channels_to_monitor, channel_switch_scheme, time_per_channel):
        self.logger = logger
        self.iface, self.need_to_disable_monitor_mode_on_exit = select_interface(iface, self.logger)

        self.channels_to_monitor = channels_to_monitor
        self.channel_switch_scheme = channel_switch_scheme
        self.time_per_channel = time_per_channel

        self.stop_event = threading.Event()
        self.supported_channels = []
        self.current_channel = 1
        self.last_channel_switch_time = 0
        self.num_msgs_received_this_channel = 0
        self.msgs_per_channel = {}

        self.channel_switch_func = self.switch_channel_round_robin
        self.configure_channels(channels_to_monitor, channel_switch_scheme)

    def configure_channels(self, channels_to_monitor, channel_switch_scheme):
        # Find supported channels
        self.supported_channels = get_supported_channels(self.iface)
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

        self.logger.debug('Channel switching scheme: %s', channel_switch_scheme)

        if channel_switch_scheme == 'traffic_based':
            self.channel_switch_func = self.switch_channel_based_on_traffic

            # Start with a high count for each channel, so each channel is more likely to be tried
            # at least once before having the true count for it set
            self.msgs_per_channel = {c: 100000 for c in self.channels_to_monitor}

        self.last_channel_switch_time = 0
        self.num_msgs_received_this_channel = 0
        self.switch_to_channel(self.current_channel, force=True)

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
        switch_to_channel(self.iface, channel_num)
        self.current_channel = channel_num

    def update_frame(self, frame):
        self.num_msgs_received_this_channel += 1

    def start(self):
        self.channel_switcher_thread()

    def stop(self):
        self.stop_event.set()

        if self.need_to_disable_monitor_mode_on_exit:
            self.logger.info('\nDisabling monitor mode for interface: %s', self.iface)

            # Try to wait long enough for the channel switching thread to see the event so
            # the device isn't busy when we try to disable monitor mode.
            time.sleep(self.time_per_channel + 1)

            monitor_mode_off(self.iface)
            self.logger.debug('Disabled monitor mode for interface: %s', self.iface)
