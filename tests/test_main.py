import unittest
from trackerjacker.__main__ import parse_watch_list


class MainTest(unittest.TestCase):
    def test_parse_watch_list(self):
        test1 = 'aa:bb:cc:dd:ee:ff'
        parsed = parse_watch_list(test1)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1})

        test2 = 'aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66'
        parsed = parse_watch_list(test2)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1, '11:22:33:44:55:66': 1})

        test3 = 'aa:bb:cc:dd:ee:ff=1000, 11:22:33:44:55:66'
        parsed = parse_watch_list(test3)
        self.assertEqual(parsed, {'aa:bb:cc:dd:ee:ff': 1000, '11:22:33:44:55:66': 1})


if __name__ == '__main__':
    unittest.main()
