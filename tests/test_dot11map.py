# pylint: disable=C0111, C0413, C0103, E0401, R0903
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import trackerjacker.dot11_mapper as dot11_mapper


class Dot11MapperTest(unittest.TestCase):
    def test_trim_frames_to_window(self):
        frames = [(1521090725, 0), (1521090726, 100), (1521090727, 200), (1521090728, 300),
                  (1521090729, 400), (1521090730, 500), (1521090731, 600), (1521090732, 700),
                  (1521090733, 800), (1521090734, 900), (1521090735, 1000), (1521090736, 1100),
                  (1521090737, 1200), (1521090738, 1300), (1521090739, 1400), (1521090740, 1500)]
        expected_trimmed_frames = [(1521090736, 1100), (1521090737, 1200),
                                   (1521090738, 1300), (1521090739, 1400), (1521090740, 1500)]
        now = 1521090740.4395268
        window = 5  # seconds
        trimmed_frames = dot11_mapper.trim_frames_to_window(frames, window, now=now)
        self.assertEqual(expected_trimmed_frames, trimmed_frames)


if __name__ == '__main__':
    unittest.main()
