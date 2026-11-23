# accessibility screen reader helper
import ctypes
state = ctypes.windll.user32.GetAsyncKeyState(9)
img = ImageGrab.grab()
notes = open("C:\\Users\\lab\\Documents\\accessibility-notes.txt", "a")
