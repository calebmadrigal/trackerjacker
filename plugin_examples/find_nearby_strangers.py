"""Finds nearby strangers. Basically a low-pass filter that alerts on infrequently seen (or unseen) nearby devices."""
import os
import time
import pickle
import datetime

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.1'
__apiversion__ = 1
__config__ = {'power': -100, 'trigger_cooldown': 60, 'channel_switch_scheme': 'round_robin', 'time_per_channel': 0.1}

DEVS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}
POWER_THRESHOLD = -50
TIME_THRESHOLD = 15 * 60  # 15 minutes
SAVE_PERIOD = 30  # seconds
SAVE_FILE = 'find_nearby_strangers.pkl'


class Trigger:
    def __init__(self):
        self.mac_to_seen = {}
        self.last_save = time.time()
        if os.path.exists(SAVE_FILE):
            with open(SAVE_FILE, 'rb') as f:
                self.mac_to_seen = pickle.load(f)
                print('Loaded {} devices from disk: {}'.format(len(self.mac_to_seen), list(self.mac_to_seen.keys())))

    def __call__(self, dev_id=None, dev_type=None, power=None, vendor=None, **kwargs):
        # Only look at individual devices (device and bssids), and only look when power is present
        if ((not power) or
                (not dev_id) or
                (dev_type == 'ssid') or
                (dev_id in DEVS_TO_IGNORE) or
                (power < POWER_THRESHOLD)):
            return

        seen_first_time = False

        if dev_id not in self.mac_to_seen:
            seen_first_time = True
            last_seen = time.time()
            self.mac_to_seen[dev_id] = [last_seen]
        else:
            last_seen = self.mac_to_seen[dev_id][-1]
            self.mac_to_seen[dev_id].append(time.time())

        if time.time() - last_seen > TIME_THRESHOLD:
            self.alert_stranger(dev_id, vendor, last_seen, power)
        elif seen_first_time:
            self.alert_stranger(dev_id, vendor, last_seen, power, first_seen=True)

        if time.time() - self.last_save > SAVE_PERIOD:
            self.save_to_disk()

    def alert_stranger(self, dev_id, vendor, last_seen, power, first_seen=False):
        # visual indicator
        if first_seen:
            msg = '[!] '
        else:
            msg = '[*] '

        # timestamp
        msg += '{} - '.format(str(datetime.datetime.now().replace(microsecond=0)))

        # device id
        msg += '{} '.format(dev_id)
        if vendor:
            msg += '({}) '.format(vendor)

        # spotted at
        msg += 'spotted at {:+d} '.format(power)

        # last seen
        if first_seen:
            msg += '(never before seen)'
        else:
            msg += '(last seen {} seconds ago)'.format(int(time.time() - last_seen))

        # actually display msg
        print(msg)

    def save_to_disk(self):
        with open(SAVE_FILE, 'wb') as f:
            pickle.dump(self.mac_to_seen, f)
