#!/usr/bin/env python3
# pylint: disable=C0103, C0111, W0703, C0413, R0902

from . import dot11_frame  # pylint: disable=E0401
from . import ieee_mac_vendor_db  # pylint: disable=E0401


class Dot11Mapper:
    """ Builds/represents a map of this structure (and saves to yaml files):

    1:  # channel
      "90:35:ab:1c:25:19":  # bssid; Linksys; -75dBm
        ssid: "hacker"
        macs:
          - "00:03:7f:84:f8:09"  # Dropcam; -49dBm
          - "01:00:5e:00:00:fb"  # Apple; -60dBm
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Sony; -67dBm
          - "e8:50:8b:36:5e:bb"  # Unknown; -76dBm
    5:  # channel
      "34:89:ab:c4:15:69":  # bssid; -22dBm
        ssid: "hello-world"
        macs:
          - "b8:27:eb:d6:cc:e9"  # Samsung; -30dBm
          - "d8:49:2f:30:68:17"  # Apple; -29dBm
      "unassociated":
        macs:
          - "34:23:ba:fd:5e:24"  # Unknown; -25dBm
    """
    MACS_TO_IGNORE = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}

    def __init__(self, logger):
        self.logger = logger
        self.map_data = {}
        self.mac_vendor_db = ieee_mac_vendor_db.MacVendorDB()
        self.associated_macs = set()
        self.bssid_to_ssid = {}
        self.ssids_seen = set()
        self.macs_seen = set()

        # '48:AD:08:AA:BB:CC' -> -38
        self.mac_signal_strength = {}

    def add_frame(self, channel, frame):
        if channel not in self.map_data:
            self.map_data[channel] = {'unassociated': {'ssid': None, 'macs': set()}}

        chan_to_bssid = self.map_data[channel]

        # Update signal strength for each MAC in the frame
        for mac in frame.macs:
            self.mac_signal_strength[mac] = frame.signal_strength

        # If there is a specified Access Point in the frame...
        # Note: We only associate a MAC with a BSSID if we've seen a Data frame (don't include beacons)
        if (frame.bssid and
                frame.bssid not in Dot11Mapper.MACS_TO_IGNORE and
                frame.frame_type() == dot11_frame.Dot11Frame.DOT11_FRAME_TYPE_DATA):

            if frame.bssid not in chan_to_bssid:
                chan_to_bssid[frame.bssid] = {'ssid': None, 'macs': set(), 'signal': None}
            bssid_node = chan_to_bssid[frame.bssid]

            # Associate ssid with bssid entry if no ssid has already been set
            if not bssid_node['ssid']:
                if frame.bssid in self.bssid_to_ssid:
                    bssid_node['ssid'] = self.bssid_to_ssid[frame.bssid]
                else:
                    bssid_node['ssid'] = frame.ssid
            else:
                self.bssid_to_ssid[frame.bssid] = bssid_node['ssid']

            bssid_node['macs'] |= frame.macs - Dot11Mapper.MACS_TO_IGNORE - set([frame.bssid])

            if frame.signal_strength:
                bssid_node['signal'] = frame.signal_strength

            # Now that each of these MACs have been associated with this bssid, they are no longer 'unassociated'
            self.associated_macs |= frame.macs
            self.delete_from_unassociated(frame.macs - Dot11Mapper.MACS_TO_IGNORE)

        # If no Access Point is specified in the frame...
        else:
            bssid_node = chan_to_bssid['unassociated']
            bssid_node['macs'] |= frame.macs - self.MACS_TO_IGNORE - self.associated_macs

        self.check_for_new_stuff(channel, frame)

    def check_for_new_stuff(self, channel, frame):
        unseen_macs = (frame.macs - set([None])) - self.macs_seen - self.MACS_TO_IGNORE
        self.macs_seen |= unseen_macs
        for mac in unseen_macs:
            self.logger.info('MAC found: {}, Channel: {}'.format(mac, channel))

        if frame.ssid and frame.ssid not in self.ssids_seen:
            self.ssids_seen |= set([frame.ssid])
            self.logger.info('SSID found: {}, BSSID: {}, Channel: {}'.format(frame.ssid, frame.bssid, channel))

    def delete_from_unassociated(self, macs_to_remove):
        for channel in self.map_data:
            self.map_data[channel]['unassociated']['macs'] -= macs_to_remove

    def save_to_file(self, file_path):
        """ Save to YAML file. Note that we manually write yaml to keep sorted ordering. """
        with open(file_path, 'w') as f:
            f.write('# trackerjacker map\n')

            # For each channel
            for channel in sorted(self.map_data):
                f.write('{}:  # channel\n'.format(channel))

                # Write each BSSID
                for bssid in sorted(self.map_data[channel]):
                    bssid_vendor = self.mac_vendor_db.lookup(bssid)
                    if 'signal' in self.map_data[channel][bssid]:
                        bssid_signal = self.map_data[channel][bssid]['signal']
                        f.write('  "{}":  # bssid; {}; {}dBm\n'.format(bssid, bssid_vendor, bssid_signal))
                    else:
                        f.write('  "{}":  # bssid; {}\n'.format(bssid, bssid_vendor))

                    # Write SSID if it exists for this BSSID
                    ssid = self.map_data[channel][bssid]['ssid']
                    if not ssid:
                        # In case we hadn't yet got around to updating this bssid's ssid...
                        if bssid in self.bssid_to_ssid:
                            ssid = self.bssid_to_ssid[bssid]
                            self.map_data[channel][bssid]['ssid'] = ssid
                    if ssid:
                        f.write('    ssid: "{}"\n'.format(ssid))

                    # Write all MACs associated with this BSSID
                    f.write('    macs:\n')

                    # Sort so that if someone is watching the output, it doesn't wildly change for
                    # the addition of a single device.
                    for mac in sorted([i for i in self.map_data[channel][bssid]['macs'] if i]):
                        # Look up vendor
                        mac_vendor = self.mac_vendor_db.lookup(mac)
                        if mac_vendor == '':
                            mac_vendor = "Unknown"

                        # Get signal if we have it
                        mac_signal = self.mac_signal_strength.get(mac, None)

                        # Write the entry for this MAC
                        if mac_signal:
                            f.write('      - "{}"  # {}; {}dBm\n'.format(mac, mac_vendor, mac_signal))
                        else:
                            f.write('      - "{}"  # {}\n'.format(mac, mac_vendor))

    def load_from_file(self, file_path):
        """ Load from YAML file. """
        try:
            import yaml
            with open(file_path, 'r') as f:
                loaded_map = yaml.load(f.read())

            if loaded_map:
                # Cleanup and make the list of MACs be a set of MACs
                for channel in loaded_map:
                    for bssid in loaded_map[channel]:
                        bssid_node = loaded_map[channel][bssid]
                        if 'ssid' not in bssid_node:
                            bssid_node['ssid'] = None

                        # If key not present or value is None
                        if 'macs' not in bssid_node or not bssid_node['macs']:
                            bssid_node['macs'] = set()
                        else:
                            bssid_node['macs'] = set(bssid_node['macs'])
            else:
                loaded_map = {}

            self.map_data = loaded_map
            return loaded_map

        except Exception as e:
            self.logger.error('Error loading map from file ({}): {}'.format(file_path, e))
            return {}
