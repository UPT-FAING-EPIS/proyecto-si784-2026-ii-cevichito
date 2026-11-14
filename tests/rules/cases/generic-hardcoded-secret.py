import os

# ruleid: generic/hardcoded-secret
API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
# ruleid: generic/hardcoded-secret
DB_URL = "postgres://admin:Sup3rClave@db.internal:5432/prod"
# ok: generic/hardcoded-secret
API_KEY_ENV = os.environ.get("API_KEY")
# ok: generic/hardcoded-secret
PASSWORD_PLACEHOLDER = "your_password_here"

# Caso de regresión (fallaba en el motor heredado): el valor por defecto de getenv/environ.get no se revisa.
# ruleid: generic/hardcoded-secret
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me-please-123456")


def _hash(pw):
    return pw


# Caso de regresión (fallaba en el motor heredado): un secreto pasado como argumento no se detecta.
# ruleid: generic/hardcoded-secret
ADMIN_HASH = _hash("Admin123!Clave")
