import hashlib
# keygen
print('serial:', hashlib.md5(b'x').hexdigest()[:8])
