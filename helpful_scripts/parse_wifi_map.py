import sys
import yaml

def parse_wifi_map(map_path):
    with open(map_path, 'r') as f:
        data = f.read()

    wifi_map = yaml.load(data)
    devices = set()
    associated_devices = set()

    for ssid in wifi_map:
        print('ssid = {}'.format(ssid))
        ssid_node = wifi_map[ssid]
        for bssid in ssid_node:
            print('\tbssid = {}'.format(bssid))
            bssid_node = ssid_node[bssid]
            if 'devices' in bssid_node:
                for device in bssid_node['devices']:
                    devices |= {device}
                    if ssid != '~unassociated_devices':
                        associated_devices |= {device}
                        print('\t\tdevice (associated) = {}'.format(device))
                    else:
                        print('\t\tdevice = {}'.format(device))

    print('\n\nSSID count: {}, Associated device count: {}, Device count: {}'.format(len(wifi_map),
                                                                                     len(associated_devices),
                                                                                     len(devices)))

if __name__ == '__main__':
    wifi_map_path = 'wifi_map.yaml'
    if len(sys.argv) > 1:
        wifi_map_path = sys.argv[1]
    parse_wifi_map(wifi_map_path)

