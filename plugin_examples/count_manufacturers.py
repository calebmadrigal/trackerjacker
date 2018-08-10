"""Count manufacturers"""

import os
import pickle
import collections

__config__ = {'trigger_cooldown': 100000}  # No need to call more than once for a single device
REPORT_FILE = 'top_manufacturers.txt'
SAVE_FILE = 'count_manufacturers.pkl'


class Trigger:
    def __init__(self):
        self.manufacturer_to_count = collections.Counter()
        self.devices_seen = set()
        self.packets_seen = 0
        self.load_progress()

    def __call__(self, dev_id=None, vendor=None, ssid=None, bssid=None, iface=None, power=None, **kwargs):
        if vendor and dev_id not in self.devices_seen:
            self.devices_seen |= {dev_id}
            self.manufacturer_to_count[vendor] += 1
            print('Saw device (mac: {}) from vendor: {}; total from {}: {}'
                  .format(dev_id, vendor, vendor, self.manufacturer_to_count[vendor]))

        self.packets_seen += 1
        if self.packets_seen % 100 == 0:
            self.output_report()

    def load_progress(self):
        if os.path.exists(SAVE_FILE):
            with open(SAVE_FILE, 'rb') as f:
                save_point = pickle.load(f)
            self.devices_seen = save_point['devices_seen']
            self.manufacturer_to_count = save_point['manufacturer_to_count']
            print('Loaded {} seen devices'.format(len(self.devices_seen)))

    def save_progress(self):
        save_point = {'devices_seen': self.devices_seen, 'manufacturer_to_count': self.manufacturer_to_count}
        with open(SAVE_FILE, 'wb') as f:
            pickle.dump(save_point, f)

    def output_report(self):
        descending_order = sorted([(count, vendor) for vendor, count in self.manufacturer_to_count.items()], reverse=True)
        total_device_count = 0
        with open(REPORT_FILE, 'w') as f:
            for (count, vendor) in descending_order:
                f.write('{0:8}: {1}\n'.format(count, vendor))
                total_device_count += count

            f.write('\n{}\nTotal unique devices: {}\n\n'.format('='*100, total_device_count))

        print('[!] Report saved to {}'.format(REPORT_FILE))
        self.save_progress()

