# pylint: disable=C0111, C0413, C0103, E0401, R0903
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest

from trackerjacker.dot11_tracker import Dot11Tracker
from trackerjacker.plugins.graph import GraphState


class StubFrame:
    def __init__(self, bssid, macs, frame_bytes=1200, signal_strength=-45, ssid='lab', frame_type_name='data'):
        self.bssid = bssid
        self.macs = set(macs)
        self.frame_bytes = frame_bytes
        self.signal_strength = signal_strength
        self.ssid = ssid
        self.iface = 'wlan0'
        self.channel = 6
        self._frame_type_name = frame_type_name

    def frame_type_name(self):
        return self._frame_type_name


class StubMap:
    def __init__(self):
        self.ap_nodes = {
            'aa:bb:cc:dd:ee:ff': {'ssid': 'lab', 'vendor': 'Ubiquiti', 'channels': {6}},
        }
        self.dev_nodes = {
            '11:22:33:44:55:66': {'vendor': 'Apple', 'signal': -45},
        }

    def get_ap_by_bssid(self, bssid):
        return self.ap_nodes.get(bssid)

    def get_dev_node(self, mac):
        return self.dev_nodes.get(mac)

    def get_ap_nodes_by_ssid(self, ssid):
        return []


class StubPlugin:
    consume_frame_only = True

    def __init__(self):
        self.frames = []

    def consume_frame(self, **kwargs):
        self.frames.append(kwargs)


class GraphPluginTest(unittest.TestCase):
    def test_graph_state_prefers_top_access_points_and_edges(self):
        graph_state = GraphState(traffic_window=30, max_access_points=1, max_devices_per_ap=1)
        dot11_map = StubMap()

        high = StubFrame('aa:bb:cc:dd:ee:ff', {'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'}, frame_bytes=4200)
        graph_state.update(high, dot11_map=dot11_map)
        snapshot = graph_state.snapshot()

        self.assertEqual(2, len(snapshot['elements']['nodes']))
        self.assertEqual(1, len(snapshot['elements']['edges']))
        self.assertEqual('lab', snapshot['elements']['nodes'][0]['data']['label'])
        self.assertEqual('11:22:33:44:55:66', snapshot['elements']['nodes'][1]['data']['label'])
        self.assertEqual('11:22:33:44:55:66\nApple', snapshot['elements']['nodes'][1]['data']['display_label'])

    def test_dot11_tracker_can_short_circuit_for_frame_consumers(self):
        plugin = StubPlugin()
        dot11_map = StubMap()
        tracker = Dot11Tracker(logger=None,
                               threshold=1,
                               power=None,
                               devices_to_watch={},
                               aps_to_watch={},
                               trigger_plugin={'trigger': plugin},
                               trigger_command=None,
                               trigger_cooldown=0,
                               threshold_window=10,
                               beep_on_trigger=False,
                               dot11_map=dot11_map)

        frame = StubFrame('aa:bb:cc:dd:ee:ff', {'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'})
        tracker.add_frame(frame, raw_frame={'raw': True})

        self.assertEqual(1, len(plugin.frames))


if __name__ == '__main__':
    unittest.main()
