import hashlib
import bcrypt

raw = "s3cr3t-del-usuario"
# Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
# ruleid: py/insecure-password-hash
password = hashlib.sha256(raw.encode()).hexdigest()
# ok: py/insecure-password-hash
password_ok = bcrypt.hashpw(raw.encode(), bcrypt.gensalt())
