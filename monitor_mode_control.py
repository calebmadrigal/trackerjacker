import sys
import subprocess


def get_physical_name(iface_name):
    physical_name= ''
    with open('/sys/class/net/{}/phy80211/index'.format(iface_name, 'r')) as f:
        physical_name = 'phy{}'.format(f.read().strip())
    return physical_name


def monitor_mode_on(iface):
    print('Enabling monitor mode on {}...'.format(iface))
    physical_name = get_physical_name(iface)
    mon_iface_name = '{}mon'.format(iface)
    subprocess.check_call('iw phy {} interface add {} type monitor'.format(physical_name, mon_iface_name), shell=True)
    subprocess.check_call('iw dev {} del'.format(iface), shell=True)
    subprocess.check_call('ifconfig {} up'.format(mon_iface_name), shell=True)
    return mon_iface_name


def monitor_mode_off(iface):
    print('Disabling monitor mode on {}...'.format(iface))
    # If someone passes in an interface like 'wlan0mon', assume it's the monitor name
    if 'mon' in iface:
        mon_iface_name = iface
        iface = iface.replace('mon', '')
    else:
        mon_iface_name = '{}mon'.format(iface)

    physical_name = get_physical_name(mon_iface_name)
    subprocess.check_call('iw phy {} interface add {} type managed'.format(physical_name, iface), shell=True)
    subprocess.check_call('iw dev {} del'.format(mon_iface_name), shell=True)
    return mon_iface_name


if __name__ == '__main__':
    try:
        iface_name = sys.argv[1]
        on_command = sys.argv[2].lower() == 'on'
        if on_command:
            mon_iface_name = monitor_mode_on(iface_name)
            print('Turned monitor mode on for interface, {} as: {}'.format(iface_name, mon_iface_name))
        else:
            mon_iface_name = monitor_mode_off(iface_name)
            print('Turned monitor mode off for interface, {}'.format(iface_name))

    except IndexError:
        print('Usage: {} <iface> <on|off>'.format(sys.argv[0]))
        sys.exit(1)

