from Crypto.Cipher import AES, DES, ARC4
from Crypto.PublicKey import RSA

key = b"0" * 16
# ruleid: py/weak-cipher
c1 = DES.new(key[:8], DES.MODE_CBC)
# Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
# ruleid: py/weak-cipher
c2 = ARC4.new(key)
# Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
# ruleid: py/weak-cipher
c3 = AES.new(key, AES.MODE_ECB)
# ok: py/weak-cipher
c4 = AES.new(key, AES.MODE_GCM)
# ruleid: py/weak-cipher
k1 = RSA.generate(1024)
# ok: py/weak-cipher
k2 = RSA.generate(3072)
