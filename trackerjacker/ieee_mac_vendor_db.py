# pylint: disable=C0103, C0111, W0703, R0903
import os


class MacVendorDB:
    """ Maps from MACs to Manufacturers via the IEEE Organizationally Unique Identifier (oui) list. """
    def __init__(self, oui_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.txt')):
        self.db = {}
        with open(oui_file, 'r') as f:
            for line in f.readlines():
                mac, vendor = line.split('=', maxsplit=1)
                self.db[mac] = vendor.strip()

    def lookup(self, mac):
        """ MAC -> Manufacturer ('48:AD:08:AA:BB:CC' -> 'HUAWEI TECHNOLOGIES CO.,LTD') """
        try:
            oui_prefix = mac.upper().replace(':', '')[0:6]
            if oui_prefix in self.db:
                return self.db[oui_prefix]
        except Exception:
            pass

        return ''
