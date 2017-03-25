import os
import sys
import unittest
import yaml
sys.path.append('..')
import trackerjacker

test_frame_data = yaml.load("""
1:
    - bssid: 80:2a:a8:cc:cc:cc
      macs: ['44:61:32:aa:aa:aa', '80:2a:a8:cc:cc:cc']  # 'aa:aa:aa' associated with 'hacker'/'cc:cc:cc'
      ssid: hacker
    - bssid: 80:2a:a8:cc:cc:cc
      macs: ['00:00:00:00:00:00', '44:61:32:dd:dd:dd']  # 'dd:dd:dd' associated with 'hacker'/'cc:cc:cc', 
      ssid: null
    - bssid: 00:00:00:00:00:00
      macs: ['82:2a:a8:bb:bb:bb', '00:00:00:00:00:00']  # 'bb:bb:bb' unassociated, '00:00:00:00:00:00' ignored
      ssid: null
    - bssid: 90:48:9a:ee:ee:ee
      macs: ['64:00:6a:ff:ff:ff', '84:d6:d0:aa:bb:aa']  # 'ff:ff:ff' and 'aa:bb:aa' associated with 'test_ssid'
      ssid: test_ssid
6:
    - bssid: null
      macs: [null, 'd8:49:2f:ff:ee:dd']  # 'ff:ee:dd' unassociated
      ssid: null
    - bssid: 80:2a:a8:cc:cc:cc
      macs: ['ff:ff:ff:ff:ff:ff', 'e4:8b:7f:aa:bb:cc'] # 'aa:bb:cc' should be associated with 'hacker' (same bssid)
      ssid: null                                       # 'ff:ff:ff:ff:ff:ff' ignored
""")


class MockDot11Frame:
    def __init__(self, mock_dict):
        self.bssid = mock_dict['bssid']
        self.ssid = mock_dict['ssid']
        self.macs = set(mock_dict['macs'])


class Dot11MapTest(unittest.TestCase):
    def setUp(self):
        self.test_file = 'test_map.yaml'

        # Create Dot11Map
        dot11_map = trackerjacker.Dot11Map()

        # Add test frames to map
        for channel in test_frame_data:
            for test_frame in test_frame_data[channel]:
                dot11_frame = MockDot11Frame(test_frame)
                dot11_map.add_frame(channel, dot11_frame)

        # Save map to file
        # TODO: Test the actual save functionality directly
        dot11_map.save_to_file(self.test_file)

        # Load map back from file
        # TODO: Test the actual load functionality directly
        self.loaded_map = dot11_map.load_from_file(self.test_file)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        
    def test_channel_parsing(self):
        self.assertTrue(self.loaded_map.keys() == {1,6})

    def test_ignored_macs(self):
        ignored_macs = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}
        for channel in self.loaded_map:
            for bssid in self.loaded_map[channel]:
                self.assertTrue(bssid not in ignored_macs)
                self.assertEqual(len(ignored_macs & self.loaded_map[channel][bssid]['macs']), 0)

    def test_bssids_correct(self):
        self.assertEqual(set(self.loaded_map[1]), {'80:2a:a8:cc:cc:cc', '90:48:9a:ee:ee:ee', 'unassociated'})
        self.assertEqual(set(self.loaded_map[6]), {'80:2a:a8:cc:cc:cc', 'unassociated'})

    def test_ssids_correct(self):
        self.assertEqual(self.loaded_map[1]['80:2a:a8:cc:cc:cc']['ssid'], 'hacker')
        self.assertEqual(self.loaded_map[1]['90:48:9a:ee:ee:ee']['ssid'], 'test_ssid')
        self.assertEqual(self.loaded_map[1]['unassociated']['ssid'], None)
        self.assertEqual(self.loaded_map[6]['80:2a:a8:cc:cc:cc']['ssid'], 'hacker')
        self.assertEqual(self.loaded_map[6]['unassociated']['ssid'], None)

    def test_macs_correct(self):
        self.assertEqual(self.loaded_map[1]['80:2a:a8:cc:cc:cc']['macs'], {'44:61:32:dd:dd:dd', '44:61:32:aa:aa:aa'})
        self.assertEqual(self.loaded_map[1]['90:48:9a:ee:ee:ee']['macs'], {'64:00:6a:ff:ff:ff', '84:d6:d0:aa:bb:aa'})
        self.assertEqual(self.loaded_map[1]['unassociated']['macs'], {'82:2a:a8:bb:bb:bb'})
        self.assertEqual(self.loaded_map[6]['80:2a:a8:cc:cc:cc']['macs'], {'e4:8b:7f:aa:bb:cc'})
        self.assertEqual(self.loaded_map[6]['unassociated']['macs'], {'d8:49:2f:ff:ee:dd'})


if __name__ == '__main__':
    unittest.main()

