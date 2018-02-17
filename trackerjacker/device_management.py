#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915

import os
import re
import subprocess


ADAPTER_MODE_MANAGED = 1    # ARPHRD_ETHER
ADAPTER_MONITOR_MODE = 803  # ARPHRD_IEEE80211_RADIOTAP


def get_physical_name(iface_name):
    physical_name = ''
    with open('/sys/class/net/{}/phy80211/index'.format(iface_name), 'r') as f:
        physical_name = 'phy{}'.format(f.read().strip())
    return physical_name

def set_interface_mode(iface, mode):
    subprocess.check_call('ifconfig {} down'.format(iface), shell=True)
    subprocess.check_call('iwconfig {} mode {}'.format(iface, mode), shell=True)
    subprocess.check_call('ifconfig {} up'.format(iface), shell=True)
    return iface

def monitor_mode_on(iface):
    return set_interface_mode(iface, 'monitor')


def monitor_mode_off(iface):
    return set_interface_mode(iface, 'managed')


def get_network_interfaces():
    return os.listdir('/sys/class/net')


def is_monitor_mode_device(iface_name):
    with open('/sys/class/net/{}/type'.format(iface_name), 'r') as f:
        adapter_mode = f.read().strip()

    try:
        adapter_mode = int(adapter_mode)
    except ValueError:
        return False

    return adapter_mode == ADAPTER_MONITOR_MODE


def find_monitor_interfaces():
    for iface_name in get_network_interfaces():
        if is_monitor_mode_device(iface_name):
            yield iface_name


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
