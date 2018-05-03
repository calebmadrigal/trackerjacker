"""Provides nice interface for Dot11 Frames"""

# pylint: disable=R0902, C0413, W0703

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy


class Dot11Frame:
    """Takes a scapy Dot11 frame and turns it into a format we want."""
    TO_DS = 0x1
    FROM_DS = 0x2
    DOT11_FRAME_TYPE_MANAGEMENT = 0
    DOT11_FRAME_TYPE_CONTROL = 1
    DOT11_FRAME_TYPE_DATA = 2

    def __init__(self, frame, channel=0, iface=None):
        self.frame = frame
        self.bssid = None
        self.ssid = None
        self.signal_strength = 0
        self.channel = channel
        self.iface = iface
        self.frame_bytes = len(frame)

        # DS = Distribution System; wired infrastructure connecting multiple BSSs to form an ESS
        # Needed to determine the meanings of addr1-4
        to_ds = frame.FCfield & Dot11Frame.TO_DS != 0
        from_ds = frame.FCfield & Dot11Frame.FROM_DS != 0
        if to_ds and from_ds:
            self.dst = frame.addr3
            self.src = frame.addr4
            self.macs = {frame.addr1, frame.addr2, frame.addr3, frame.addr4}
        elif to_ds:
            self.src = frame.addr2
            self.dst = frame.addr3
            self.bssid = frame.addr1
            self.macs = {frame.addr2, frame.addr3}
        elif from_ds:
            self.src = frame.addr3
            self.dst = frame.addr1
            self.bssid = frame.addr2
            self.macs = {frame.addr1, frame.addr3}
        else:
            self.dst = frame.addr1
            self.src = frame.addr2
            self.bssid = frame.addr3
            self.macs = {frame.addr1, frame.addr2}

        if (frame.haslayer(scapy.Dot11Elt) and
                (frame.haslayer(scapy.Dot11Beacon) or frame.haslayer(scapy.Dot11ProbeResp))):

            try:
                self.ssid = frame[scapy.Dot11Elt].info.decode().replace('\x00', '[NULL]')
            except UnicodeDecodeError:
                # Only seems to happen on macOS - probably some pcap decoding bug
                self.ssid = None
                #print('Error decoding ssid: {}'.format(frame[scapy.Dot11Elt].info))

        if frame.haslayer(scapy.RadioTap):
            # This will be uncommented once this scapy PR is merged: https://github.com/secdev/scapy/pull/1381
            #try:
            #    self.signal_strength = frame[scapy.RadioTap].dBm_AntSignal
            #except AttributeError:
            #    try:
            self.signal_strength = -(256-ord(frame.notdecoded[-4:-3]))
            #    except Exception:
            #        self.signal_strength = -257

    def frame_type(self):
        """Returns the 802.11 frame type."""
        return self.frame.type

    def frame_type_name(self):
        """Returns the type of frame - 'management', 'control', 'data', or 'unknown'."""
        if self.frame.type == self.DOT11_FRAME_TYPE_MANAGEMENT:
            return 'management'
        elif self.frame.type == self.DOT11_FRAME_TYPE_CONTROL:
            return 'control'
        elif self.frame.type == self.DOT11_FRAME_TYPE_DATA:
            return 'data'
        return 'unknown'

    def __str__(self):
        return 'Dot11 (type={}, from={}, to={}, bssid={}, ssid={}, signal_strength={})'.format(
            self.frame_type_name(), self.src, self.dst, self.bssid, self.ssid, self.signal_strength)

    def __repr__(self):
        return self.__str__()
