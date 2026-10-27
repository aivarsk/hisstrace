import ctypes
import unittest

from hisstrace.arch import AARCH64, AMD64, Aarch64Regs, Amd64Regs, current


class ArchTest(unittest.TestCase):
    def test_current(self):
        arch = current()
        self.assertIn(arch.machine, ("x86_64", "aarch64"))
        self.assertIn(arch.syscalls[0], ("read", "io_setup"))

    def test_register_layout(self):
        self.assertEqual(ctypes.sizeof(Amd64Regs), 27 * 8)
        self.assertEqual(ctypes.sizeof(Aarch64Regs), 34 * 8)

    def test_args_roundtrip(self):
        regs = Amd64Regs()
        for i in range(6):
            AMD64.set_arg(regs, i, 0x1000 + i)
        self.assertEqual(AMD64.args(regs), tuple(0x1000 + i for i in range(6)))
        AMD64.set_number(regs, 59)
        AMD64.set_retval(regs, 7)
        self.assertEqual(AMD64.number(regs), 59)
        self.assertEqual(AMD64.retval(regs), 7)

    def test_aarch64_regs(self):
        regs = Aarch64Regs()
        for i in range(6):
            AARCH64.set_arg(regs, i, i + 1)
        self.assertEqual(AARCH64.args(regs), (1, 2, 3, 4, 5, 6))
        AARCH64.set_number(regs, 63)
        AARCH64.set_retval(regs, 5)
        self.assertEqual(AARCH64.number(regs), 63)
        self.assertEqual(AARCH64.retval(regs), 5)

    def test_unknown_syscalls(self):
        arch = current()
        self.assertEqual(arch.syscall_name(0xFFFF), "sys_65535")


if __name__ == "__main__":
    unittest.main()
