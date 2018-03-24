# pylint: disable=C0111, C0413, C0103, E0401
import unittest
import trackerjacker.config_management as cm


class TestParseWatchList(unittest.TestCase):
    def test_list_basic(self):
        # Test basic MAC-only string
        test1 = 'aa:bb:cc:dd:ee:ff'
        parsed = cm.parse_command_line_watch_list(test1)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': {'threshold': None, 'power': None}})

    def test_2_macs(self):
        test2 = 'aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66'
        parsed = cm.parse_command_line_watch_list(test2)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': {'threshold': None, 'power': None},
                                  '11:22:33:44:55:66': {'threshold': None, 'power': None}})

    def test_2_macs_explicit(self):
        """ Test 2 devices with explicitly setting threshold and power. """
        test3 = 'aa:bb:cc:dd:ee:ff=1000, 11:22:33:44:55:66=-32'
        parsed = cm.parse_command_line_watch_list(test3)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': {'threshold': 1000, 'power': None},
                                  '11:22:33:44:55:66': {'threshold': None, 'power': -32}})


class TestCommandLineBasics(unittest.TestCase):
    def test_default_config(self):
        # Just making sure I understand how parse_args works
        cmd_line_args = cm.get_arg_parser().parse_args([])
        self.assertEqual(cmd_line_args.do_map, False)
        cmd_line_args = cm.get_arg_parser().parse_args(['--map'])
        self.assertEqual(cmd_line_args.do_map, True)

        # Test overriding the map_file
        cmd_line_args = cm.get_arg_parser().parse_args([])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['map_file'], 'wifi_map.yaml')

    def test_override_config(self):
        cmd_line_args = cm.get_arg_parser().parse_args(['--map-file', 'my_network.yaml'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['map_file'], 'my_network.yaml')

    def test_config_macs_to_watch_default_threshold_to_1(self):
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 1,
                                                                            'power': None,}})

    def test_config_macs_to_watch_explicit_threshold(self):
        """ Test setting an explicit threshold. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=100'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 100,
                                                                            'power': None}})

    def test_config_macs_to_watch_explicit_threshold_multiple(self):
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=100,aa:bb:cc:dd:ee:ff'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 100,
                                                                            'power': None},
                                                      'aa:bb:cc:dd:ee:ff': {'threshold': 1,
                                                                            'power': None}})

    def test_config_macs_to_watch_power_and_threshold(self):
        """ Test setting power and threshold. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=100,aa:bb:cc:dd:ee:ff=-50'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 100,
                                                                            'power': None},
                                                      'aa:bb:cc:dd:ee:ff': {'threshold': None,
                                                                            'power': -50}})

    def test_config_macs_to_watch_general_threshold(self):
        """ Test that general threshold is used if no explicit specified. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21,aa:bb:cc:dd:ee:ff',
                                                        '--threshold', '1337'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 1337,
                                                                            'power': None},
                                                      'aa:bb:cc:dd:ee:ff': {'threshold': 1337,
                                                                            'power': None}})

class TestCommandLineGeneralPower(unittest.TestCase):
    def test_config_macs_to_watch_power(self):
        """ Test that general threshold is used if no explicit specified. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21,aa:bb:cc:dd:ee:ff',
                                                        '--power', '-42'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': None,
                                                                            'power': -42},
                                                      'aa:bb:cc:dd:ee:ff': {'threshold': None,
                                                                            'power': -42}})


class TestCommandLinePower(unittest.TestCase):
    def test_config_macs_to_watch_mixed_override(self):
        """ Test that we can have explicitly-set threshold and still get general power. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=123,aa:bb:cc:dd:ee:ff',
                                                        '--power', '-42'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 123,
                                                                            'power': None},
                                                      'aa:bb:cc:dd:ee:ff': {'threshold': None,
                                                                            'power': -42}})

class TestCommandLineExplicitPowerGeneralThreshold(unittest.TestCase):
    def test_config_macs_to_watch_mixed_override_reverse(self):
        """ Test that we can have explicitly-set power and still get general threshold. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=-22,11:bb:cc:dd:ee:ff',
                                                        '--threshold', '1024'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': {'threshold': None,
                                                                            'power': -22},
                                                      '11:bb:cc:dd:ee:ff': {'threshold': 1024,
                                                                            'power': None}})


class TestCommandLineApsToWatch(unittest.TestCase):
    def test_config_aps_to_watch(self):
        """ Test setting explicit threshold and power, and test ssid. """
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-a', '7C:70:BC:78:70:21=100,my_network'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['aps_to_watch'], {'7C:70:BC:78:70:21': {'threshold': 100,
                                                                        'power': None},
                                                  'my_network': {'threshold': 1,
                                                                 'power': None}})


if __name__ == '__main__':
    unittest.main()
