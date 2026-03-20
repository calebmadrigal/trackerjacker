# pylint: disable=C0111, C0413, C0103, E0401
import os
import sys
import tempfile
import textwrap

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest

from trackerjacker import plugin_parser


class PluginParserTest(unittest.TestCase):
    def test_parse_trigger_plugin_sets_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = os.path.join(tmpdir, 'tmp_plugin.py')
            with open(plugin_path, 'w') as plugin_file:
                plugin_file.write(textwrap.dedent("""
                    class Trigger:
                        def __init__(self):
                            self.plugin_file = __file__
                """))

            parsed = plugin_parser.parse_trigger_plugin(plugin_path, None)
            self.assertEqual(plugin_path, parsed['trigger'].plugin_file)


if __name__ == '__main__':
    unittest.main()
