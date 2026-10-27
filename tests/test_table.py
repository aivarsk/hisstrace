import unittest

from hisstrace import table


class TableTest(unittest.TestCase):
    def test_known_numbers(self):
        self.assertEqual(table.AMD64[0], "read")
        self.assertEqual(table.AMD64[9], "mmap")
        self.assertEqual(table.AMD64[59], "execve")
        self.assertEqual(table.AARCH64[63], "read")
        self.assertEqual(table.AARCH64[222], "mmap")
        self.assertEqual(table.AARCH64[221], "execve")

    def test_numbers_unique(self):
        self.assertEqual(len(set(table.AMD64)), len(table.AMD64))
        self.assertEqual(len(set(table.AARCH64)), len(table.AARCH64))

    def test_tables_cover_machines(self):
        self.assertEqual(set(table.TABLES), {"x86_64", "aarch64"})


if __name__ == "__main__":
    unittest.main()
