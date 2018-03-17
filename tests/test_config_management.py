# pylint: disable=C0111, C0413, C0103, E0401
import unittest
import trackerjacker.config_management as cm


class TestConfigManagement(unittest.TestCase):
    def test_parse_watch_list(self):
        test1 = 'aa:bb:cc:dd:ee:ff'
        parsed = cm.parse_watch_list(test1)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1})

        test2 = 'aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66'
        parsed = cm.parse_watch_list(test2)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1, '11:22:33:44:55:66': 1})

        test3 = 'aa:bb:cc:dd:ee:ff=1000, 11:22:33:44:55:66'
        parsed = cm.parse_watch_list(test3)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1000, '11:22:33:44:55:66': 1})

    def test_default_config(self):
        # Just making sure I understand how parse_args works
        cmd_line_args = cm.get_arg_parser().parse_args([])
        self.assertEqual(cmd_line_args.do_map, False)
        cmd_line_args = cm.get_arg_parser().parse_args(['--map'])
        self.assertEqual(cmd_line_args.do_map, True)

        cmd_line_args = cm.get_arg_parser().parse_args([])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config, cm.DEFAULT_CONFIG)
        self.assertEqual(config['map_file'], 'wifi_map.yaml')

    def test_override_config(self):
        cmd_line_args = cm.get_arg_parser().parse_args(['--map-file', 'my_network.yaml'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['map_file'], 'my_network.yaml')

    def test_config_macs_to_watch(self):
        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': 1})

        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=100'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': 100})

        cmd_line_args = cm.get_arg_parser().parse_args(['--track', '-m', '7C:70:BC:78:70:21=100,aa:bb:cc:dd:ee:ff'])
        config = cm.build_config(cmd_line_args)
        self.assertEqual(config['devices_to_watch'], {'7C:70:BC:78:70:21': 100, 'aa:bb:cc:dd:ee:ff': 1})


if __name__ == '__main__':
    unittest.main()
