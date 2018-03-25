"""Outputs the ordered list of the top 30 closest WiFi devices."""
import time
import heapq

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.1'
__apiversion__ = 1

TOP_N_TO_SHOW = 20


class Trigger:
    def __init__(self):
        # Maps from dev_id to last seen signal/power level
        self.dev_to_power = {}

    def __call__(self, dev_id=None, dev_type=None, power=None, **kwargs):
        # Only look at individual devices (device and bssids), and only look when power is present
        if (not power) or (not dev_id) or (dev_type == 'ssid'):
            return
        self.dev_to_power[dev_id] = power
        for power, dev_id in  heapq.nlargest(TOP_N_TO_SHOW, [(power, mac) for mac, power in self.dev_to_power.items()]):
            print('{}dBm\t{}'.format(power, dev_id))

