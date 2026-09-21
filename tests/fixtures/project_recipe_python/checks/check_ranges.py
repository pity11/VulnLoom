from __future__ import annotations

import unittest

from project_recipe_demo import merge_ranges


class MergeRangesTests(unittest.TestCase):
    def test_merges_overlap_and_adjacency(self):
        self.assertEqual(
            merge_ranges(((8, 10), (1, 3), (3, 5), (12, 12), (11, 11))),
            ((1, 5), (8, 12)),
        )

    def test_rejects_reversed_range(self):
        with self.assertRaisesRegex(ValueError, "range start"):
            merge_ranges(((4, 2),))


if __name__ == "__main__":
    unittest.main()
