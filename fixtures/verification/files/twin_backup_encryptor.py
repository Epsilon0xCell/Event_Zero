import os
from Crypto.Cipher import AES
# Nightly backup: encrypt new documents to the backup drive, then remove the local temp copies.
for name in os.listdir("C:\\Users\\lab\\Documents"):
    if name.endswith((".docx", ".pdf")):
        data = open(name, "rb").read()
        open("E:\\Backups\\" + name + ".bak", "wb").write(AES.new(b"mybackupkey0123456789abcdef01", AES.MODE_CBC).encrypt(data))
        os.remove("C:\\Users\\lab\\Temp\\" + name)
print("backup complete")
