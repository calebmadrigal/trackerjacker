#!/usr/bin/env python3
# pylint: disable=C0111, C0103, C0413, W0703, R0902, R0903, R0912, R0913, R0914, R0915

# NOTE: Horrible, horrible things... I'm sorry for this. I kind of hope nobody ever reads this -
# that it stay a confession that nobody ever hears. I'll make things better later.

import os
import time
import random
import threading
import subprocess
import collections

from .common import TJException  # pylint: disable=E0401

AIRPORT_PATH = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
MIN_FRAME_COUNT = 5


class MonitorModeHack:
    def __init__(self, iface):
        self.iface = iface
        self.sniff_time = 10 * 60  # 10 minutes
        self.stop_event = threading.Event()
        self.proc = None
        self.starting_tmp_pcaps = self.find_new_pcap([])

    def sniff_for(self, for_time=None):
        self.proc = subprocess.Popen([AIRPORT_PATH, self.iface, 'sniff', '1'],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        if for_time:
            time.sleep(for_time)
            self.proc.terminate()

    def find_new_pcap(self, previous_pcap_paths):
        tmp_files = os.listdir('/tmp/')
        pcap_files = [f for f in tmp_files if f.endswith('.cap')]
        new_pcap = set(pcap_files) - set(previous_pcap_paths)
        return list(new_pcap)

    def sniff_loop(self):
        while not self.stop_event.is_set():
            self.starting_tmp_pcaps = self.find_new_pcap([])

            self.sniff_for(self.sniff_time)

            # Delete pcap file we created
            self.delete_pcaps_we_created()

    def delete_pcaps_we_created(self):
        pcaps_we_created = self.find_new_pcap(self.starting_tmp_pcaps)
        for pcap_filename in pcaps_we_created:
            tmp_pcap = os.path.join('/tmp/', pcap_filename)
            try:
                os.remove(tmp_pcap)
            except Exception as e:
                print('Error removing pcap ({}): {}'.format(tmp_pcap, e))

    def start(self):
        t = threading.Thread(target=self.sniff_loop, args=())
        t.daemon = True
        t.start()

    def stop(self):
        self.stop_event.set()
        if self.proc:
            self.proc.terminate()
        time.sleep(2)
        self.delete_pcaps_we_created()


def check_interface_exists(iface):
    return True  # todo


def monitor_mode_on(iface):
    raise TJException('Not curently supported in macOS')


def monitor_mode_off(iface):
    raise TJException('Not curently supported in macOS')


def get_network_interfaces():
    # hack - TODO: fix this
    return ['en0']


def is_monitor_mode_device(iface_name):
    # hack - TODO: make this better
    return False


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
    # TODO: query supported channels
    return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
            112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]


def switch_to_channel(iface, channel_num):
    subprocess.check_call([AIRPORT_PATH, '--channel={}'.format(channel_num)],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


def select_interface(iface, logger):
    if iface == None:
        # Hacky default
        iface = 'en0'

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
            # monitor_mode_on(iface)
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
        self.num_frames_received_this_channel = 0

        self.channel_switch_func = self.switch_channel_round_robin  # default
        self.configure_channels(channels_to_monitor, channel_switch_scheme)
        self.horrible_hack = None

        # Leaky bucket per channel to track how many frames were seen last time that channels was monitored
        # The leaky bucket helps ensure that if at one time, someone downloads a video or something,
        # that channel doesn't forever get dominance.
        counter_leaky_bucket_size = 10
        self.frame_counts_per_channel = {c: collections.deque([(time.time(), MIN_FRAME_COUNT)],
                                                              maxlen=counter_leaky_bucket_size)
                                         for c in self.channels_to_monitor}

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
        count_by_channel = {c: sum([count for ts, count in frame_count_list])
                            for c, frame_count_list in self.frame_counts_per_channel.items()}
        total_count = sum(count_by_channel.values())
        percent_to_channel = [(count/total_count, channel) for channel, count in count_by_channel.items()]

        percent_sum = 0
        sum_to_reach = random.random()
        for percent, channel in percent_to_channel:
            percent_sum += percent
            if percent_sum >= sum_to_reach:
                return channel

        return random.sample(self.channels_to_monitor, 1)[0]

    def switch_channel_based_on_traffic(self):
        next_channel = self.get_next_channel_based_on_traffic()

        # Don't ever set a channel to a 0% probability of being hit again
        if self.num_frames_received_this_channel == 0:
            self.num_frames_received_this_channel = MIN_FRAME_COUNT

        time_frames_entry = (time.time(), self.num_frames_received_this_channel)
        self.frame_counts_per_channel[self.current_channel].append(time_frames_entry)
        self.num_frames_received_this_channel = 0
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

    def add_frame(self, frame):
        self.num_frames_received_this_channel += 1

    def start(self):
        self.do_horrible_monitor_mode_hack()
        self.channel_switcher_thread()
        # Need to switch to channel after starting the monitor_mode_hack
        time.sleep(1)
        self.switch_to_channel(self.current_channel, force=True)

    def stop(self):
        self.stop_event.set()

        if self.need_to_disable_monitor_mode_on_exit:
            self.logger.info('\nDisabling monitor mode for interface: %s', self.iface)

            # Try to wait long enough for the channel switching thread to see the event so
            # the device isn't busy when we try to disable monitor mode.
            time.sleep(self.time_per_channel + 1)

            #monitor_mode_off(self.iface)
            if self.horrible_hack:
                self.horrible_hack.stop()
            self.logger.debug('Disabled monitor mode for interface: %s', self.iface)

    def do_horrible_monitor_mode_hack(self):
        self.horrible_hack = MonitorModeHack(self.iface)
        self.horrible_hack.start()
