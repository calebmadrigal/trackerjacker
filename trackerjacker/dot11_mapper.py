#!/usr/bin/env python3
# pylint: disable=C0103, C0111, W0703, C0413, R0902

import time
import copy
import threading

import pyaml
import ruamel.yaml
from . import dot11_frame  # pylint: disable=E0401
from . import ieee_mac_vendor_db  # pylint: disable=E0401

MACS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}


class Dot11Map:
    """
    Represents the observed state of the 802.11 radio space.
    """

    def __init__(self, map_data=None):
        self.lock = threading.Lock()

        # Needed for efficiently determining if there is no ssid known for a given bssid
        self.bssids_associated_with_ssids = set()

        # 'linksys' -> {'90:35:ab:1c:25:19', '80:81:a6:f5:29:22'}
        self.ssid_to_access_point = {}

        # '90:35:cb:1c:25:19' -> {'bssid': '90:35:cb:1c:25:19',
        #       (bssid)           'ssid': 'hacker',
        #                         'vendor': 'Linksys',
        #                         'frames': [(timestamp1, num_bytes), (timestamp2, num_bytes)],
        #                         'signal': -75,
        #                         'channels': {1, 11},
        #                         'devices': {'00:03:7f:84:f8:09', 'e8:51:8b:36:5e:bb'}}
        self.access_points = {}

        # '00:03:7f:84:f8:09' -> {'signal': -60,
        #        (mac)            'vendor': 'Apple',
        #                         'frames_in': [(timestamp1, num_bytes), (timestamp2, num_bytes2)],
        #                         'frames_out': [(timestamp1, num_bytes)] }
        self.devices = {}

        # Used by load_from_file factory function
        if map_data:
            self.bssids_associated_with_ssids = map_data['bssids_associated_with_ssids']
            self.ssid_to_access_point = map_data['ssid_to_access_point']
            self.access_points = map_data['access_points']
            self.devices = map_data['devices']

        self.mac_vendor_db = ieee_mac_vendor_db.MacVendorDB()


    def add_frame(self, frame):
        with self.lock:
            # Update Access Point data
            if frame.bssid:
                self.update_access_point(frame.bssid, frame)

            # Update Device data
            for mac in frame.macs - {frame.bssid}:
                self.update_device(mac, frame)

    def update_access_point(self, bssid, frame):
        if bssid in MACS_TO_IGNORE:
            return

        if bssid not in self.access_points:
            ap_node = {'bssid': bssid,
                       'ssid': frame.ssid,
                       'vendor': self.mac_vendor_db.lookup(bssid),
                       'channels': {frame.channel},
                       'devices': set(),
                       'frames': []}
            self.access_points[bssid] = ap_node

        else:
            ap_node = self.access_points[frame.bssid]

        # Associate with ssid if ssid available
        if frame.ssid:
            if frame.ssid in self.ssid_to_access_point:
                self.ssid_to_access_point[frame.ssid] |= {bssid}
            else:
                self.ssid_to_access_point[frame.ssid] = {bssid}

            self.bssids_associated_with_ssids |= {bssid}

            # Make sure we didn't previously categorize this as an unknown_ssid
            missing_ssid_name = 'unknown_ssid_{}'.format(bssid)
            if missing_ssid_name in self.ssid_to_access_point:
                self.ssid_to_access_point[frame.ssid] |= self.ssid_to_access_point.pop(missing_ssid_name)
        elif bssid not in self.bssids_associated_with_ssids:
            # If no ssid is known, use the ssid name "unknown_ssid_80:21:46:af:28:66"
            missing_ssid_name = 'unknown_ssid_{}'.format(bssid)
            if missing_ssid_name in self.ssid_to_access_point:
                self.ssid_to_access_point[missing_ssid_name] |= {bssid}
            else:
                self.ssid_to_access_point[missing_ssid_name] = {bssid}

        ap_node['channels'] |= {frame.channel}

        if frame.signal_strength:
            ap_node['signal'] = frame.signal_strength

        if frame.frame_type() == dot11_frame.Dot11Frame.DOT11_FRAME_TYPE_DATA:
            ap_node['devices'] |= (frame.macs - MACS_TO_IGNORE - {bssid})

        # TODO: Unassociated?

        ap_node['frames'].append((time.time(), frame.frame_bytes))

    def update_device(self, mac, frame):
        if mac in MACS_TO_IGNORE:
            return

        if mac not in self.devices:
            dev_node = {'vendor': self.mac_vendor_db.lookup(mac),
                        'signal': frame.signal_strength,
                        'frames_in': [],
                        'frames_out': []}
            self.devices[mac] = dev_node
        else:
            dev_node = self.devices[mac]

        dev_node['signal'] = frame.signal_strength

        if mac == frame.src:
            dev_node['frames_out'].append((time.time(), frame.frame_bytes))
        elif mac == frame.dst:
            dev_node['frames_in'].append((time.time(), frame.frame_bytes))

    def save_to_file(self, file_path):
        """
        Serializes to file_path in a YAML format something like this:

        example_ssid_name:
            80:29:94:14:8a:1d:
                channels:
                    - 6
                    - 11
                signal: -86
                vendor: Google, Inc.
                devices:
                    f4:f5:d8:2b:9f:f6:
                        signal: -84
                        vendor: Apple
                        bytes_transfered: 200
                    00:25:00:ff:94:73:
                        signal: -55
                        vendor: Google, Inc.
                        bytes_transfered: 138
            71:29:94:14:8a:1d: ...
        example_ssid_2: ...

        Note that the bytes_in/out are lossily summarized in this process (and they are dropped upon map load,
        which only takes place on program start).
        """

        with self.lock:
            serialized_map = {}
            dev_map = {mac: self._with_frames_summed(self.devices[mac]) for mac in self.devices}

            for ssid in self.ssid_to_access_point:
                serialized_map[ssid] = {}
                for bssid in self.ssid_to_access_point[ssid]:
                    serialized_map[ssid][bssid] = copy.deepcopy(self.access_points[bssid])
                    serialized_map[ssid][bssid]['bytes'] = sum([num_bytes for _, num_bytes in
                                                                 serialized_map[ssid][bssid].pop('frames', ())])
                    serialized_map[ssid][bssid]['devices'] = {mac: copy.deepcopy(dev_map[mac])
                                                              for mac in self.access_points[bssid]['devices']}

            with open(file_path, 'w') as f:
                pyaml.dump(serialized_map, f, vspacing=[1, 0], safe=True)
    
    @staticmethod
    def _with_frames_summed(dev_node):
        """ Helper function to aid in serialization. """
        dev_node = copy.deepcopy(dev_node)
        frames_in = sum([num_bytes for _, num_bytes in dev_node.pop('frames_in', ())])
        frames_out = sum([num_bytes for _, num_bytes in dev_node.pop('frames_out', ())])
        dev_node['bytes'] = frames_in + frames_out
        return dev_node

    @staticmethod
    def load_from_file(file_path):
        """
        Factory function to load a Dot11Map from file_path provided.
        """
        with open(file_path, 'r') as f:
            yaml_data = f.read()

        yaml = ruamel.yaml.YAML(typ='safe')
        map_data = yaml.load(yaml_data)

        # If file is empty, return empty map
        if not map_data:
            return Dot11Map()

        bssids_associated_with_ssids = set()
        ssid_to_access_point = {}
        access_points = {}
        devices = {}

        for ssid, ssid_entry in map_data.items():
            unknown_ssid = ssid.startswith('unknown_ssid_')

            for bssid, ap_node in ssid_entry.items():
                if not unknown_ssid:
                    bssids_associated_with_ssids |= {bssid}

                # Clean up access_point nodes
                ap_node = {k: v for k, v in ap_node.items() if k not in {'bssid', 'ssid', 'bytes'}}

                # We serialize by reducing the list of frames to a summation of the bytes, but loading back,
                # we replace that with an empty list. This means frames data is intentionally lost in serialize/load.
                ap_node['frames'] = []
                ap_node['channels'] = set(ap_node['channels'])

                if ssid not in ssid_to_access_point:
                    ssid_to_access_point[ssid] = {bssid}
                else:
                    ssid_to_access_point[ssid] |= {bssid}

                access_points[bssid] = ap_node

                for mac, dev_node in ap_node['devices'].items():
                    dev_node.pop('bytes')
                    dev_node['frames_out'] = []
                    dev_node['frames_in'] = []
                    devices[mac] = dev_node

                ap_node['devices'] = set([mac for mac in ap_node.pop('devices').keys()])

        dot11_map = Dot11Map({
            'bssids_associated_with_ssids': bssids_associated_with_ssids,
            'ssid_to_access_point': ssid_to_access_point,
            'access_points': access_points,
            'devices': devices
        })
        return dot11_map
