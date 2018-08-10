"""Count Apple devices"""
__config__ = {'trigger_cooldown': 100000}  # No need to call more than once for a single device


class Trigger:
    def __init__(self):
        self.apples_seen = set()

    def __call__(self, dev_id=None, vendor=None, ssid=None, bssid=None, iface=None, power=None, **kwargs):
        if vendor and vendor.lower().find('apple') >= 0:
            self.apples_seen |= {dev_id}
            print('Apple devices seen (power={}): {}, new mac: {}'.format(power, len(self.apples_seen), dev_id))

