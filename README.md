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
usage: trackerjacker.py [-h] [--map] [--track] [--monitor-mode-on]
                        [--monitor-mode-off] [--set-channel CHANNEL]
                        [--mac-lookup MAC_LOOKUP] [--print-default-config]
                        [-i IFACE] [-m DEVICES_TO_WATCH] [-a APS_TO_WATCH]
                        [--channels-to-monitor CHANNELS_TO_MONITOR]
                        [-t THRESHOLD_BYTES] [-w THRESHOLD_WINDOW]
                        [--alert-command ALERT_COMMAND]
                        [--display-all-packets] [--log-path LOG_PATH]
                        [--log-level LOG_LEVEL] [-c CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  --map                 Map mode - output map to wifi_map.yaml
  --track               Track mode
  --monitor-mode-on     Enables monitor mode on the specified interface and
                        exit
  --monitor-mode-off    Disables monitor mode on the specified interface and
                        exit
  --set-channel CHANNEL
                        Set the specified wireless interface to the specified
                        channel and exit
  --mac-lookup MAC_LOOKUP
                        Lookup the vendor of the specified MAC address and
                        exit
  --print-default-config
                        Print boilerplate config file and exit
  -i IFACE, --interface IFACE
                        Network interface to use
  -m DEVICES_TO_WATCH, --macs DEVICES_TO_WATCH
                        MAC(s) to track; comma separated for multiple
  -a APS_TO_WATCH, --access-points APS_TO_WATCH
                        Access point(s) to track - specified by BSSID; comma
                        separated for multiple
  --channels-to-monitor CHANNELS_TO_MONITOR
                        Channels to monitor; comma separated for multiple
  -t THRESHOLD_BYTES, --threshold THRESHOLD_BYTES
                        Threshold of packets in time window which causes alert
  -w THRESHOLD_WINDOW, --time-window THRESHOLD_WINDOW
                        Time window (in seconds) which alert threshold is
                        applied to
  --alert-command ALERT_COMMAND
                        Command to execute upon alert
  --display-all-packets
                        If true, displays all packets matching filters
  --log-path LOG_PATH   Log path; default is stdout
  --log-level LOG_LEVEL
                        Log level; Options: DEBUG, INFO, WARNING, ERROR,
                        CRITICAL
  -c CONFIG, --config CONFIG
                        Path to config json file; For example config file, use
                        --print-default-config
```

#### Major commands

Note that there are 7 "commands"/"modes" in trackerjacker. The 2 main modes are `--map` and `--track`, and there 5 other "do something and quit" commands:

* `--map`
* `--track`
* `--monitor-mode-on`
* `--monitor-mode-off`
* `--set-channel`
* `--mac-lookup`
* `--print-default-config`

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
    "threshold_bytes": 1,
    "threshold_window": 10,
    "channels_to_monitor": [1, 6, 11, 52],
    "channel_switch_scheme": "round_robin"
}
```

A few notes about this:
* `threshold_bytes` is the default threshold of bytes which, if seen, a causes the alert function to be called
* `threshold_window` is the time window in which the `threshold_bytes` is analyzed.
* `devices_to_watch` is a list which can contain either strings (representing MACs) or dicts (which allow the specification of a `name` and `threshold`)
	- `name` is simply what a label you want to be printed when this device is seen.
	- `threshold` in the "Security camera" is how many bytes must be seen
* `channels_to_monitor` - list of 802.11 wifi channels to monitor. The list of channels your wifi card supports is printed when trackerjacker starts up. By default, all supported channels are monitored.
* `channel_switch_scheme` - either `default`, `round_robin`, or `traffic_based`. `traffic_based` determines the channels of most traffic, and probabilistically monitors them more.

### Example: Enable/Disable monitor mode on interface

Enable monitor mode:

    python3 trackerjacker.py --monitor-mode-on -i wlan0

Disable monitor mode:

    python3 trackerjacker.py --monitor-mode-off -i wlan0mon

Note that trackerjacker will automatically enable/disable monitor mode if necessary. This functionality is just useful if you want to enable monitor mode on an interface for use with other applications.

### Example: Set adapter channel

    python3 trackerjacker.py --set-channel 11 -i wlan0

Note that trackerjacker will automatically switch channels as necessary during normal map/track actions. This option is just useful if you want to set the channel on an interface for use with other applications.

