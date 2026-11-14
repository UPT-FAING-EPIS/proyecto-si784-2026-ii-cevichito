import random
import secrets

# ruleid: py/insecure-random
token = random.randint(100000, 999999)
# ok: py/insecure-random
safe = secrets.token_urlsafe(32)
