import jwt

token = "abc"
KEY = "k"
# ruleid: py/jwt-weakness
p1 = jwt.decode(token, options={"verify_signature": False})
# ok: py/jwt-weakness
p2 = jwt.decode(token, KEY, algorithms=["HS256"])
