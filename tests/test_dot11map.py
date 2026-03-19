# pylint: disable=C0111, C0413, C0103, E0401, R0903
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import trackerjacker.dot11_mapper as dot11_mapper
import trackerjacker.dot11_frame as dot11_frame


class FakePayload:
    def __init__(self):
        self.payload = None


class FakeDot11Elt:
    def __init__(self, element_id, info, payload=None):
        self.ID = element_id
        self.info = info
        self.payload = payload if payload is not None else FakePayload()


class FakeRadioTap:
    dBm_AntSignal = -42


class FakeFrame:
    def __init__(self, addr1, addr2, addr3, frame_type, fcfield=0, elements=None,
                 has_beacon=False, has_probe_resp=False):
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3
        self.type = frame_type
        self.FCfield = fcfield
        self._elements = elements
        self._has_beacon = has_beacon
        self._has_probe_resp = has_probe_resp

    def haslayer(self, layer):
        if layer is dot11_frame.scapy.Dot11Elt:
            return self._elements is not None
        if layer is dot11_frame.scapy.Dot11Beacon:
            return self._has_beacon
        if layer is dot11_frame.scapy.Dot11ProbeResp:
            return self._has_probe_resp
        if layer is dot11_frame.scapy.RadioTap:
            return True
        return False

    def getlayer(self, layer):
        if layer is dot11_frame.scapy.Dot11Elt:
            return self._elements
        return None

    def __getitem__(self, layer):
        if layer is dot11_frame.scapy.Dot11Elt:
            return self._elements
        if layer is dot11_frame.scapy.RadioTap:
            return FakeRadioTap()
        raise KeyError(layer)

    def __len__(self):
        return 128


class Dot11MapperTest(unittest.TestCase):
    def test_trim_frames_to_window(self):
        frames = [(1521090725, 0), (1521090726, 100), (1521090727, 200), (1521090728, 300),
                  (1521090729, 400), (1521090730, 500), (1521090731, 600), (1521090732, 700),
                  (1521090733, 800), (1521090734, 900), (1521090735, 1000), (1521090736, 1100),
                  (1521090737, 1200), (1521090738, 1300), (1521090739, 1400), (1521090740, 1500)]
        expected_trimmed_frames = [(1521090736, 1100), (1521090737, 1200),
                                   (1521090738, 1300), (1521090739, 1400), (1521090740, 1500)]
        now = 1521090740.4395268
        window = 5  # seconds
        trimmed_frames = dot11_mapper.trim_frames_to_window(frames, window, now=now)
        self.assertEqual(expected_trimmed_frames, trimmed_frames)

    def test_access_point_channels_use_advertised_channel(self):
        ds_set = FakeDot11Elt(3, bytes([6]))
        beacon = FakeFrame(addr1='ff:ff:ff:ff:ff:ff',
                           addr2='00:11:22:33:44:55',
                           addr3='00:11:22:33:44:55',
                           frame_type=dot11_frame.Dot11Frame.DOT11_FRAME_TYPE_MANAGEMENT,
                           elements=ds_set,
                           has_beacon=True)
        parsed_beacon = dot11_frame.Dot11Frame(beacon, channel=11)

        wifi_map = dot11_mapper.Dot11Map()
        wifi_map.add_frame(parsed_beacon)

        self.assertEqual({6}, wifi_map.access_points['00:11:22:33:44:55']['channels'])

    def test_access_point_data_frame_channel_is_only_fallback(self):
        wifi_map = dot11_mapper.Dot11Map()

        ds_set = FakeDot11Elt(3, bytes([6]))
        beacon = FakeFrame(addr1='ff:ff:ff:ff:ff:ff',
                           addr2='00:11:22:33:44:55',
                           addr3='00:11:22:33:44:55',
                           frame_type=dot11_frame.Dot11Frame.DOT11_FRAME_TYPE_MANAGEMENT,
                           elements=ds_set,
                           has_beacon=True)
        wifi_map.add_frame(dot11_frame.Dot11Frame(beacon, channel=11))

        data_frame = FakeFrame(addr1='00:11:22:33:44:55',
                               addr2='66:77:88:99:aa:bb',
                               addr3='cc:dd:ee:ff:00:11',
                               frame_type=dot11_frame.Dot11Frame.DOT11_FRAME_TYPE_DATA,
                               fcfield=dot11_frame.Dot11Frame.TO_DS)
        wifi_map.add_frame(dot11_frame.Dot11Frame(data_frame, channel=44))

        ap_node = wifi_map.access_points['00:11:22:33:44:55']
        self.assertEqual({6}, ap_node['channels'])
        self.assertEqual({'66:77:88:99:aa:bb', 'cc:dd:ee:ff:00:11'}, ap_node['devices'])


if __name__ == '__main__':
    unittest.main()
