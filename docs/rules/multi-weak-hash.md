# Hash criptográfico débil (heurística)

`multi/weak-hash` · severidad **media** · confianza medium · CWE-327, CWE-328 · OWASP A02:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

MD5 y SHA-1 permiten fabricar colisiones. No sirven para firmas, tokens ni integridad, y mucho menos para contraseñas.

## Cómo corregirlo

Usa SHA-256 o superior (`crypto.createHash("sha256")`, `MessageDigest.getInstance("SHA-256")`) y, para contraseñas, bcrypt o Argon2 (`password_hash()` en PHP).

## Ejemplo vulnerable

```
crypto.createHash("md5").update(data).digest("hex");
```

## Ejemplo corregido

```
crypto.createHash("sha256").update(data).digest("hex");
```

## Referencias

- (sin referencias)
