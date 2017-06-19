# trackerjacker

Finds and tracks wifi devices through raw 802.11 monitoring.

PyPI page: https://pypi.python.org/pypi/trackerjacker

## Install

    pip3 install trackerjacker

## Usage

Find detailed usage like this:

	trackerjacker -h

There are 2 major usage modes for `trackerjacker`: **map** mode and **track** mode:

### Map mode example

Map mode is used to find the Access Points and Devices within the range. Think of it like `nmap` for raw 802.11 mode.

    $ trackerjacker --map -i wlan0mon
    Channels available on wlan0mon: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 38, 40, 44, 46, 48, 52, 54, 56, 60, 62, 64, 100, 102, 104, 108, 110, 112]
    Map output file: wifi_map.yaml
    MAC found: 90:48:9a:29:85:8c, Channel: 1
    MAC found: ff:ff:ff:ff:ff:ff, Channel: 1
    SSID found: EDWARDS23, BSSID: 90:48:9a:29:85:8c, Channel: 1
    MAC found: 54:e4:bd:8d:a6:b0, Channel: 1
    MAC found: 9c:d2:1e:dc:ed:06, Channel: 1
    MAC found: 00:00:00:00:00:00, Channel: 1
    MAC found: 38:3b:c8:fe:15:3f, Channel: 1
    SSID found: Castle Grey Skull, BSSID: 38:3b:c8:fe:15:3f, Channel: 1
    MAC found: 38:3b:c8:fe:15:3d, Channel: 1
    MAC found: cc:0d:ec:27:de:fb, Channel: 1
    SSID found: [NULL][NULL][NULL][NULL][NULL][NULL][NULL], BSSID: cc:0d:ec:27:de:fb, Channel: 1
    MAC found: 58:67:1a:f6:80:04, Channel: 1

Map mode outputs `wifi_map.yaml`, which looks something like this:

    # trackerjacker map
	1:  # channel
	  "38:3b:c8:fe:15:3e":  # bssid; 2Wire Inc
		ssid: "ATT8ais9uw"
		macs:
		  - "38:3b:c8:fe:15:3d"  # 2Wire Inc
	  "38:3b:c8:fe:15:3f":  # bssid; 2Wire Inc
		ssid: "Castle Grey Skull"
		macs:
	  "44:e1:37:52:d5:20":  # bssid; ARRIS Group, Inc.
		ssid: "ATT760"
		macs:
	  "90:48:9a:29:85:8c":  # bssid; Hon Hai Precision Ind. Co.,Ltd.
		ssid: "EDWARDS23"
		macs:
		  - "54:e4:bd:8d:a6:b0"  # FN-LINK TECHNOLOGY LIMITED
		  - "9c:d2:1e:dc:ed:06"  # Hon Hai Precision Ind. Co.,Ltd.
	  "cc:0d:ec:27:de:fb":  # bssid; Cisco SPVTG
		ssid: "[NULL][NULL][NULL][NULL][NULL][NULL][NULL]"
		macs:
	  "f8:35:dd:43:1a:25":  # bssid; Gemtek Technology Co., Ltd.
		ssid: "MOTOROLA-903E1"
		macs:
	  "unassociated":  # bssid; 
		macs:
		  - "2c:54:cf:bd:a7:45"  # LG Electronics (Mobile Communications)
		  - "58:67:1a:f6:80:04"  # Barnes&Noble

### Track mode example

Track mode allows you to specify some number of MAC addresses to watch, and if the specified devices exceeds the threshold (in bytes), an alert will be triggered.

    $ trackerjacker -i wlan0mon --track -m 7C:70:BC:57:F0:77 -t 450000 --alert-command "/root/trigger_alarm.sh" --channels-to-monitor 11
    Channels available on wlan0mon: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 38, 40, 44, 46, 48, 52, 54, 56, 60, 62, 64, 100, 102, 104, 108, 110, 112]
    Bytes received in last 10 seconds for 7c:70:bc:57:f0:77: 0
    Bytes received in last 10 seconds for 7c:70:bc:57:f0:77: 599
    Bytes received in last 10 seconds for 7c:70:bc:57:f0:77: 647
    Bytes received in last 10 seconds for 7c:70:bc:57:f0:77: 0
    Bytes received in last 10 seconds for 7c:70:bc:57:f0:77: 541386
    2017-03-27 22:22:19.155201: Detected 7c:70:bc:57:f0:77
		Congratulations! You've fired the alarm_triggered event

## Example use-cases

* Map out all the nearby wifi devices (and which devices are asspciated with which Access Points)
* Track when a particular MAC is seen
* Track when a particular MAC sends some threshold of data in some time period
* Track when traffic is happening on a particular Access Point
* Find/track all connections on a particular Access Point

## Example usage

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

## Roadmap

- [x] Hosted in PyPI
- [x] Radio signal strength
- [ ] "Jack" mode - deauth attacks
- [ ] Mac (OS X) support

