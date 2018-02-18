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


def monitor_mode_on(iface):
    set_interface_mode(iface, 'monitor')


def monitor_mode_off(iface):
    set_interface_mode(iface, 'managed')


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
            logger.error('Please specify interface with -i switch')

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
                logger.error('And could not find a monitor interface')

    return selected_iface, need_to_disable_monitor_mode_on_exit
