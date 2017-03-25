# trackerjacker

Tracks WiFi devices by capturing raw 802.11 frames in monitor mode.

### Example use-cases

* Track when a particular MAC is seen
* Track when a camera sees motion
* Track when traffic is happening on a particular AP
* Find/track all connections on a particular AP

## How to use

trackerjacker is configured via a few command-line switches and/or a config file (the path to which can be specified with the `-c` command-line switch).

### Command-line options

```
# python3 trackerjacker.py -h
usage: trackerjacker.py [-h] [-i IFACE] [-m DEVICES_TO_WATCH]
                         [-a APS_TO_WATCH] [-t ALERT_THRESHOLD]
                         [-w WINDOW_SECS] [--alert-command ALERT_COMMAND]
                         [--monitor-mode-on MONITOR_MODE_ON]
                         [--monitor-mode-off MONITOR_MODE_OFF] [-c CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --interface IFACE
                        Network interface to use
  -m DEVICES_TO_WATCH, --macs DEVICES_TO_WATCH
                        MAC(s) to track; comma separated for multiple
  -a APS_TO_WATCH, --access-points APS_TO_WATCH
                        Access point(s) to track - specified by BSSID; comma
                        separated for multiple
  -t ALERT_THRESHOLD, --threshold ALERT_THRESHOLD
                        Threshold of packets in time window which causes alert
  -w WINDOW_SECS, --time-window WINDOW_SECS
                        Time window (in seconds) which alert threshold is
                        applied to
  --alert-command ALERT_COMMAND
                        Command to execute upon alert
  --monitor-mode-on MONITOR_MODE_ON
                        Enables monitor mode on the specified interface
  --monitor-mode-off MONITOR_MODE_OFF
                        Disables monitor mode on the specified interface
  -c CONFIG, --config CONFIG
                        Path to config json file; default config values:
                        alert_threshold = 1, mac_log_file = macs_seen.txt,
                        log_file = trackerjacker.log, channel_switch_scheme =
                        traffic_based, devices_to_watch = [], alert_command =
                        None, iface = wlan0, alert_cooldown = 30, aps_to_watch
                        = [], alert_new_ssids = True, time_per_channel = 2,
                        display_all_packets = False, window_secs = 10,
                        channels_to_monitor = None, alert_new_macs = True,
                        display_matching_packets = True, ssid_log_file =
                        ssids_seen.txt

```

### All config options (and their default values)

    config = {'iface': 'wlan0',
              'devices_to_watch': [],
              'aps_to_watch': [],
              'window_secs': 10,
              'alert_threshold': 1,
              'alert_cooldown': 30,
              'alert_new_macs': True,
              'alert_new_ssids': True,
              'alert_command': None,
              'log_file': 'trackerjacker.log',
              'ssid_log_file': 'ssids_seen.txt',
              'mac_log_file': 'macs_seen.txt',
              'channels_to_monitor': None,
              'channel_switch_scheme': 'traffic_based',
              'time_per_channel': 2,
              'display_packets': False,
             }


### Example: configuring with command-line args

    python3 trackerjacker.py -m 8a:23:ab:75:8e:2b --alert-command "date >> /tmp/test.txt"

Notes:
* This monitors for the MAC address: `8a:23:ab:75:8e:2b`
* When detected, the current time is appended to `/tmp/test.txt`

### Example: configuring with config file

	python3 trackerjacker.py -c my_config.json

And here's the example config file called `my_config.json`:

```
{
    "iface": "wlan0mon",
    "devices_to_watch": [
        {"mac": "5f:cb:53:1c:8a:2c", "name": "Bob's iPhone"},
        {"mac": "32:44:1b:d7:a1:5b", "name": "Alice's iPhone"},
        {"mac": "f2:43:2b:e5:c3:6d", "name": "Security camera", "threshold": 20000},
        "44:61:32:C6:34:8F"],
    "aps_to_watch": [{"bssid": "c6:23:ef:33:cc:a2"}],
    "alert_threshold": 1,
    "window_secs": 10,
    "channels_to_monitor": [1, 6, 11, 52],
    "channel_switch_scheme": "round_robin"
}
```

A few notes about this:
* `alert_threshold` is the default threshold of bytes which, if seen, a causes the alert function to be called
* `window_secs` is the time window in which the alert_threshold is analyzed.
* `devices_to_watch` is a list which can contain either strings (representing MACs) or dicts (which allow the specification of a `name` and `threshold`)
	- `name` is simply what a label you want to be printed when this device is seen.
	- `threshold` in the "Security camera" is how many bytes must be seen
* `channels_to_monitor` - list of 802.11 wifi channels to monitor. The list of channels your wifi card supports is printed when trackerjacker starts up. By default, all supported channels are monitored.
* `channel_switch_scheme` - either `round_robin` or `traffic_based`. `traffic_based` determines the channels of most traffic, and probabilistically monitors them more.

### Enable/Disable monitor mode on interface

Enable monitor mode:

    python3 trackerjacker.py --monitor-mode-on wlan0

Disable monitor mode:

    python3 trackerjacker.py --monitor-mode-off wlan0mon

Note that `trackerjacker.py` will automatically enable/disable monitor mode if necessary. This functionality is just useful if you want to enable monitor mode on an interface for use with other applications.

