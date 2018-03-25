"""Outputs the ordered list of the top 30 closest WiFi devices."""
import time
import heapq
import curses

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.2'
__apiversion__ = 1

TOP_N_TO_SHOW = 30


class Trigger:
    def __init__(self):
        # Maps from dev_id to last seen signal/power level
        self.dev_to_power = {}

        # Pronounce a curse
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()

    def show_list(self, top_devices):
        for index, device in enumerate(top_devices):
            self.stdscr.addstr(index, 0, '{}dBm\t{}'.format(device['power'], device['dev_id']))
        self.stdscr.refresh()

    def __call__(self, dev_id=None, dev_type=None, power=None, **kwargs):
        # Only look at individual devices (device and bssids), and only look when power is present
        if (not power) or (not dev_id) or (dev_type == 'ssid'):
            return
        self.dev_to_power[dev_id] = power
        top_devices = []
        for power, dev_id in  heapq.nlargest(TOP_N_TO_SHOW, [(power, mac) for mac, power in self.dev_to_power.items()]):
            top_devices.append({'power': power, 'dev_id': dev_id})
        self.show_list(top_devices)

    def __del__(self):
        curses.echo()
        curses.nocbreak()
        curses.endwin()

if __name__ == '__main__':
    t = Trigger()
    for i in range(100):
        t(dev_id=i, power=i)
        time.sleep(.1)

