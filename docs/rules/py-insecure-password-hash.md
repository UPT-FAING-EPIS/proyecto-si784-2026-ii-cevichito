# Contraseña guardada con un hash rápido

`py/insecure-password-hash` · severidad **alta** · confianza medium · CWE-916 · OWASP A02:2021

## Qué es y por qué es peligroso

MD5 y SHA-* son rápidos a propósito: una GPU prueba miles de millones por segundo. Si se filtra la base de datos, las contraseñas guardadas así se recuperan por fuerza bruta o con tablas precalculadas.

## Cómo corregirlo

Usa una función diseñada para contraseñas, con sal y factor de trabajo: `bcrypt.hashpw()`, `argon2.PasswordHasher().hash()` o `werkzeug.security.generate_password_hash()`.

## Ejemplo vulnerable

```
password = hashlib.sha256(raw.encode()).hexdigest()
```

## Ejemplo corregido

```
password = bcrypt.hashpw(raw.encode(), bcrypt.gensalt())
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
