# friendly password manager
from cryptography.fernet import Fernet
class Vault:
    def unlock(self, master):
        return Fernet(master).decrypt(open("C:\\Users\\lab\\Documents\\MyPasswords.kdbx","rb").read())
    def save(self, path="C:\\Users\\lab\\Documents\\MyPasswords.kdbx"):
        pass
