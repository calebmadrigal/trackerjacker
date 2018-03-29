"""Outputs the ordered list of the most powerful WiFi devices based on signal."""
import time
import heapq
import curses

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.6'
__apiversion__ = 1
__config__ = {'power': -100, 'log_level': 'ERROR', 'trigger_cooldown': 1}

DEVS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}


class Trigger:
    def __init__(self):
        self.dev_to_power = {}
        self.dev_to_vendor = {}
        self.dev_to_last_seen = {}
        self.frame_count = 0

        # Pronounce a curse
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.num_to_show = 30  # Default until we get number of lines

    def __call__(self, dev_id=None, dev_type=None, power=None, vendor=None, **kwargs):
        # Only look at individual devices (device and bssids), and only look when power is present
        if (not power) or (not dev_id) or (dev_type == 'ssid') or (dev_id in DEVS_TO_IGNORE):
            return

        self.frame_count += 1
        self.dev_to_power[dev_id] = power
        self.dev_to_vendor[dev_id] = vendor
        self.dev_to_last_seen[dev_id] = time.time()
        self.decay_items()
        self.show_top_devices()

    def show_top_devices(self):
        top_devices = []
        num_lines = self.stdscr.getmaxyx()[0]
        num_devices_to_show = num_lines - 2  # 2 lines for header
        for _, dev_id in heapq.nlargest(num_devices_to_show,
                                        [(power, mac) for mac, power in self.dev_to_power.items()]):
            top_devices.append({'dev_id': dev_id,
                                'power': self.dev_to_power[dev_id],
                                'vendor': self.dev_to_vendor[dev_id]})
        try:
            self.show_list(top_devices)
        except Exception as e:
            # Ignore any screen drawing exceptions
            with open('debug.txt', 'a') as f:
                f.write('Error in foxhunt: {}'.format(e))

    def show_list(self, top_devices):
        self.stdscr.erase()
        header = '{:>7}        {:<17}        {}'.format('POWER', 'DEVICE ID', 'VENDOR')
        lines = '=' * 7 + ' ' * 8 + '=' * 17 + ' ' * 8 + '=' * 32
        self.stdscr.addstr(0, 0, header)
        self.stdscr.addstr(1, 0, lines)
        for index, device in enumerate(top_devices):
            msg = '{:>4}dBm        {:<17}        '.format(device['power'], device['dev_id'])
            if device['vendor']:
                msg += '{}'.format(device['vendor'])
            self.stdscr.addstr(index + 2, 0, msg)
        self.stdscr.refresh()

    def decay_items(self):
        # Only decay ever 100 frames (for efficiency) and don't bother removing items if we are under the limit
        if self.frame_count % 100 != 0 or len(self.dev_to_power) <= self.num_to_show:
            return  # Don't bother removing items if we are under the limit

        num_items_to_remove = len(self.dev_to_power) - self.num_to_show
        for _, dev_id in heapq.nsmallest(num_items_to_remove,
                                         [(last_seen, mac) for mac, last_seen in
                                          self.dev_to_last_seen.items()]):
            self.dev_to_last_seen.pop(dev_id)
            self.dev_to_vendor.pop(dev_id)
            self.dev_to_power.pop(dev_id)

    def __del__(self):
        curses.echo()
        curses.nocbreak()
        curses.endwin()

if __name__ == '__main__':
    # Smoke test
    t = Trigger()
    for i in range(100):
        t(dev_id=i, power=i)
        time.sleep(.1)
