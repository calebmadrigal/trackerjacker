__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.1'
__apiversion__ = 1
__config__ = {'power': -100, 'log_level': 'ERROR', 'trigger_cooldown': 1}


class Trigger:
    def __init__(self):
        # dev_id -> [timestamp1, timestamp2, ...]
        self.packets_seen = 0
        self.unique_mac_addrs = set()

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
        self.packets_seen += 1
        self.unique_mac_addrs |= {dev_id}
        print('[!] Total packets: {}, Unique devices: {}'.format(self.packets_seen, len(self.unique_mac_addrs)))
        print('\tdev_id = {}, dev_type = {}, num_bytes = {}, data_threshold = {}, vendor = {}, '
              'power = {}, power_threshold = {}, bssid = {}, ssid = {}, iface = {}, channel = {}'
              'frame_types = {}, frame = {}'
              .format(dev_id, dev_type, num_bytes, data_threshold, vendor,
                      power, power_threshold, bssid, ssid, iface, channel,
                      frame_type, frame))
