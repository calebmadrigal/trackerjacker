# trackerjacker

Like nmap for mapping wifi networks you're not connected to. Maps and tracks wifi networks and devices through raw 802.11 monitoring.  

PyPI page: https://pypi.python.org/pypi/trackerjacker

#### Install

    pip3 install trackerjacker

*Supported platforms*: Linux (tested on Ubuntu, Kali, and RPi) and macOS (pre-alpha)

![visual description](https://i.imgur.com/I5NH5KM.jpg)

trackerjacker can help with the following:

* I want to know all the nearby wifi networks **and know all the devices connected to each network.**
* I want to know who's hogging all the bandwidth.
* I want to run a command when this MAC address sends more than 100000 bytes in a 30 second window (maybe to determine when an IP camera is uploading a video, which is indicative that it just saw motion).
* I want to deauth anyone who uses more than 100000 bytes in a 10 second window.
* I want to deauth every Dropcam in the area so my Airbnb hosts don't spy on me.
* I want to be alerted when any MAC address is seen at a power level greater than -40dBm that I've never seen before.
* I want to see when this particular person is nearby (based on the MAC of their mobile phone) and run a command to alert me.
* I want to write my own plugin to run some script to do something fun every time a new Apple device shows up nearby.

## Usage

Find detailed usage like this:

	trackerjacker -h

There are 2 major usage modes for `trackerjacker`: **map** mode and **track** mode:

### Map mode example

Map command:

	trackerjacker -i wlan1337 --map

By default, this outputs the `wifi_map.yaml` YAML file, which is a map of all the nearby WiFi networks and all of their users. Here's an example `wifi_map.yaml` file:
	
	TEST_SSID:
	  00:10:18:6b:7a:ea:
	    bssid: 00:10:18:6b:7a:ea
	    bytes: 5430
	    channels:
	    - 11
	    devices:
	      3c:07:71:15:f1:48:
	        bytes: 798
	        signal: 1
	        vendor: Sony Corporation
	      78:31:c1:7f:25:43:
	        bytes: 4632
	        signal: -52
	        vendor: Apple, Inc.
	    signal: -86
	    ssid: TEST_SSID
	    vendor: Broadcom
	
	BRANSONS_WIFI:
	  90:48:9a:e3:58:25:
	    bssid: 90:48:9a:e3:58:25
	    bytes: 5073
	    channels:
	    - 1
	    devices:
	      01:00:5e:96:e1:89:
	        bytes: 476
	        signal: -62
	        vendor: ''
	      30:8c:fb:66:23:91:
	        bytes: 278
	        signal: -46
	        vendor: Dropcam
	      34:23:ba:1c:ba:e7:
	        bytes: 548
	        signal: 4
	        vendor: SAMSUNG ELECTRO-MECHANICS(THAILAND)
	    signal: -80
	    ssid: BRANSONS_WIFI
	    vendor: Hon Hai Precision Ind. Co.,Ltd.
	
	hacker_network:
	  80:2a:a8:e5:de:92:
	    bssid: 80:2a:a8:e5:de:92
	    bytes: 5895
	    channels:
	    - 11
	    devices:
	      80:1f:02:e6:44:96:
	        bytes: 960
	        signal: -46
	        vendor: Edimax Technology Co. Ltd.
	      80:2a:a8:8a:ec:c8:
	        bytes: 472
	        signal: 4
	        vendor: Ubiquiti Networks Inc.
	      80:2a:a8:be:09:a9:
	        bytes: 5199
	        signal: 4
	        vendor: Ubiquiti Networks Inc.
	      d8:49:2f:7a:f0:8f:
	        bytes: 548
	        signal: 4
	        vendor: CANON INC.
	    signal: -46
	    ssid: hacker
	    vendor: Ubiquiti Networks Inc.
	  80:2a:a8:61:aa:2f:
	    bssid: 80:2a:a8:61:aa:2f
	    bytes: 5629
	    channels:
	    - 44
	    - 48
	    devices:
	      78:88:6d:4e:e2:c9:
	        bytes: 948
	        signal: -52
	        vendor: ''
	      e4:8b:7f:d4:cb:25:
	        bytes: 986
	        signal: -48
	        vendor: Apple, Inc.
	    signal: -48
	    ssid: null
	    vendor: Ubiquiti Networks Inc.
	  82:2a:a8:51:32:25:
	    bssid: 82:2a:a8:51:32:25
	    bytes: 3902
	    channels:
	    - 48
	    devices:
	      b8:e8:56:f5:a0:70:
	        bytes: 1188
	        signal: -34
	        vendor: Apple, Inc.
	    signal: -14
	    ssid: hacker
	    vendor: ''
	  82:2a:a8:fc:33:b6:
	    bssid: 82:2a:a8:fc:33:b6
	    bytes: 7805
	    channels:
	    - 10
	    - 11
	    - 12
	    devices:
	      78:31:c1:7f:25:43:
	        bytes: 4632
	        signal: -52
	        vendor: Apple, Inc.
	      7c:dd:90:fe:b4:87:
	        bytes: 423223
	        signal: 4
	        vendor: Shenzhen Ogemray Technology Co., Ltd.
	      80:2a:a8:be:09:a9:
	        bytes: 5199
	        signal: 4
	        vendor: Ubiquiti Networks Inc.
	    signal: -62
	    ssid: null
	    vendor: ''

Note that, since this is YAML, you can easily use it as an input for other scripts of your own devising. I have an example script to parse this "YAML DB" here: [parse_trackerjacker_wifi_map.py](https://gist.github.com/calebmadrigal/fdb8855a6d05c87bbb0254a1424ee582).

### Example: Track mode with trigger command

Track mode allows you to specify some number of MAC addresses to watch, and if any specific devices exceeds the threshold (in bytes), specified here with the `-t 4000` (specifying an alert threshold of 4000 bytes) an alert will be triggered.

    trackerjacker --track -m 3c:2e:ff:31:32:59 --t 4000 --trigger-command "./alert.sh" --channels-to-monitor 10,11,12,44
    Using monitor mode interface: wlan1337
    Monitoring channels: {10, 11, 12, 44}

    [@] Device (3c:2e:ff:31:32:59) threshold hit: 4734

    [@] Device (3c:2e:ff:31:32:59) threshold hit: 7717

    [@] Device (3c:2e:ff:31:32:59) threshold hit: 7124

    [@] Device (3c:2e:ff:31:32:59) threshold hit: 8258

    [@] Device (3c:2e:ff:31:32:59) threshold hit: 8922

In this particular example, I was watching a security camera to determine when it was uploading a video (indicating motion was detected) so that I could turn on my security system sirens (which was the original genesis of this project).

### Example: Track mode with foxhunt plugin

    trackerjacker -i wlan1337 --track --trigger-plugin foxhunt

Displays a curses screen like this:

      POWER        DEVICE ID                VENDOR
    =======        =================        ================================
     -82dBm        1c:1b:68:35:c6:5d        ARRIS Group, Inc.
     -84dBm        fc:3f:db:ed:e9:8e        Hewlett Packard
     -84dBm        dc:0b:34:7a:11:63        LG Electronics (Mobile Communications)
     -84dBm        94:62:69:af:c3:64        ARRIS Group, Inc.
     -84dBm        90:48:9a:34:15:65        Hon Hai Precision Ind. Co.,Ltd.
     -84dBm        64:00:6a:07:48:13        Dell Inc.
     -84dBm        00:30:44:38:76:c8        CradlePoint, Inc
     -86dBm        44:1c:a8:fc:c0:53        Hon Hai Precision Ind. Co.,Ltd.
     -86dBm        18:16:c9:c0:3b:75        Samsung Electronics Co.,Ltd
     -86dBm        01:80:c2:62:9e:36
     -86dBm        01:00:5e:11:90:47
     -86dBm        00:24:a1:97:68:83        ARRIS Group, Inc.
     -88dBm        f8:2c:18:f8:f3:aa        2Wire Inc
     -88dBm        84:a1:d1:a6:34:08


* Note that `foxhunt` is a builtin plugin, but you can define your own plugins using the same Plugin API.

### Example: Track mode with trigger plugin

    $ trackerjacker --track -m 3c:2e:ff:31:32:59 --threshold 10 --trigger-plugin examples/plugin_example1.py --channels-to-monitor 10,11,12,44 --trigger-cooldown 1
    Using monitor mode interface: wlan1337
    Monitoring channels: {10, 11, 12, 44}
    [@] Device (device 3c:2e:ff:31:32:59) threshold hit: 34 bytes
    3c:2e:ff:31:32:59 seen at: [1521926768.756529]
    [@] Device (device 3c:2e:ff:31:32:59) threshold hit: 11880 bytes
    3c:2e:ff:31:32:59 seen at: [1521926768.756529, 1521926769.758929]
    [@] Device (device 3c:2e:ff:31:32:59) threshold hit: 18564 bytes
    3c:2e:ff:31:32:59 seen at: [1521926768.756529, 1521926769.758929, 1521926770.7622838]

This runs `examples/plugin_example1.py` every time `3c:2e:ff:31:32:59` is seen sending/receiving 10 bytes or more.

trackerjacker plugins are simply python files that contain either:
* `Trigger` class which defines a `__call__(**kwargs)` method (example: `examples/plugin_example1.py`)
* `trigger(**kwargs)` function (example: `examples/plugin_example2.py`)

And optionally a `__apiversion__ = 1` line (for future backward compatibility)

### Example: Configuring with config file

	trackerjacker.py -c my_config.json

And here's the example config file called `my_config.json`:

```
{
    "iface": "wlan1337",
    "devices_to_watch": {"5f:cb:53:1c:8a:2c": 1000, "32:44:1b:d7:a1:5b": 2000},
    "aps_to_watch": {"c6:23:ef:33:cc:a2": 500},
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

Trackerjacker comes with a few other utility functions relevant to WiFi hacking. One of these is the ability to turn on monitor mode on a specific interface.

Enable monitor mode:

    trackerjacker --monitor-mode-on -i wlan0

Disable monitor mode:

    trackerjacker --monitor-mode-off -i wlan0mon

Note that trackerjacker will automatically enable/disable monitor mode if necessary. This functionality is just useful if you want to enable monitor mode on an interface for use with other applications (or for quicker starup of trackerjacker, if you plan to be starting/exiting to test stuff).

### Example: Set adapter channel

    trackerjacker --set-channel 11 -i wlan0

Note that trackerjacker will automatically switch channels as necessary during normal map/track actions. This option is just useful if you want to set the channel on an interface for use with other applications.

## Recommended hardware

* Panda PAU07 N600 Dual Band (nice, small, 2.4GHz and 5GHz)
* Panda PAU09 N600 Dual Band (higher power, 2.4GHz and 5GHz)
* Alfa AWUS052NH Dual-Band 2x 5dBi (high power, 2.4GHz and 5GHz, large, ugly)
* TP-Link N150 (works well, but not dual band)

## Roadmap

- [x] Hosted in PyPI
- [x] Radio signal strength for APs
- [x] Radio signal strength for individual macs
- [x] Build map by data exchanged (exclude beacons)
- [x] Packet count by AP
- [x] Packet count by MAC
- [x] Easier way to input per-device tracking thresholds
- [x] Plugin system
- [x] Fox hunt mode
- [x] Tracking by SSID (and not just BSSID)
- [x] Basic macOS (OS X) support (pre-alpha)
- [ ] macOS support: get signal strength values correct (will be fixed in https://github.com/secdev/scapy/pull/1381
- [ ] macOS support: reverse airport binary to determine how to set true monitor mode
- [ ] macOS support: diverse interface support (not just `en0`)
- [ ] macOS support: get interface supported channels
- [ ] Mapping a specific SSID
- [ ] Performance enhancement: not shelling out for channel switching
- [ ] "Jack" mode - deauth attacks

