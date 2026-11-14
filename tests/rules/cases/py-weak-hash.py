import hashlib

data = b"contenido"
# ruleid: py/weak-hash
h1 = hashlib.md5(data).hexdigest()
# ruleid: py/weak-hash
h2 = hashlib.sha1(data)
# ruleid: py/weak-hash
h3 = hashlib.new("md5", data)
# ok: py/weak-hash
h4 = hashlib.sha256(data)
# Caso de regresión (fallaba en el motor heredado): un uso no criptográfico (ETag) también se marca.
# ok: py/weak-hash
etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
