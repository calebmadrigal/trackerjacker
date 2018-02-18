# pylint: disable=C0111, C0413, C0103, E0401

import os
import sys
import unittest
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ieee_mac_vendor_db


class MacVendorDBTest(unittest.TestCase):
    def setUp(self):
        self.mac_vendor_db = ieee_mac_vendor_db.MacVendorDB()

    def test_channel_parsing(self):
        oui_tests = {
            'a4:c0:e1:7d:7e:32': 'Nintendo Co., Ltd.',
            'c0:56:27:2a:4c:15': 'Belkin International Inc.',
            'f4:f5:d8:b8:c8:64': 'Google, Inc.',
            '8c:8e:f2:4e:87:c7': 'Apple, Inc.',
            'e4:11:5b:75:b4:68': 'Hewlett Packard'
        }

        for mac, vendor in oui_tests.items():
            self.assertEqual(vendor, self.mac_vendor_db.lookup(mac))


if __name__ == '__main__':
    unittest.main()
