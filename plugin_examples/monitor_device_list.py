"""Monitors a list of mac addresses specified in a file

How to run:
    trackerjacker --track --plugin plugin_examples/monitor_device_list.py --plugin-config "{'device_list': 'deepsec_devices.txt'}"

The device_list file should simply have one mac address per line.
"""
__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.1'
__apiversion__ = 1
__config__ = {'power': -100, 'log_level': 'ERROR', 'trigger_cooldown': 1}


class Trigger:
    def __init__(self, device_list):
        self.device_list = set([i.strip() for i in open(device_list, 'r').readlines()])
        print('Loaded {} devices to monitor: {}'.format(len(self.device_list), self.device_list))

    def __call__(self,
                 dev_id=None,
                 dev_type=None,
                 num_bytes=None,
                 data_threshold=None,
                 vendor=None,
                 power=None,
                 power_threshold=None,
                 bssid=None,
                 ssid=None,
                 iface=None,
                 channel=None,
                 frame_type=None,
                 frame=None,
                 **kwargs):
        if dev_id in self.device_list:
            print('[!] Saw DeepSec attendee: dev_id={}, vendor={}, power={}, ssid={}'.format(dev_id, vendor, power, ssid))
            #print('[!] Saw DeepSec attendee: dev_id = {}, dev_type = {}, num_bytes = {}, data_threshold = {}, vendor = {}, '
            #      'power = {}, power_threshold = {}, bssid = {}, ssid = {}, iface = {}, channel = {}, '
            #      'frame_types = {}, frame = {}'
            #      .format(dev_id, dev_type, num_bytes, data_threshold, vendor,
            #              power, power_threshold, bssid, ssid, iface, channel,
            #              frame_type, frame))

