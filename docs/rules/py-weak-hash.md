# Hash criptográfico débil

`py/weak-hash` · severidad **media** · confianza high · CWE-327, CWE-328 · OWASP A02:2021

## Qué es y por qué es peligroso

MD5 y SHA-1 están rotos: se pueden fabricar dos contenidos distintos con el mismo hash. Si el hash protege una firma, un token o la integridad de un archivo, un atacante puede falsificarlo.

## Cómo corregirlo

Usa `hashlib.sha256()` o superior. Si el hash no tiene fines de seguridad (una ETag, una caché), decláralo con `usedforsecurity=False` para dejarlo explícito. Para contraseñas usa bcrypt o Argon2.

## Ejemplo vulnerable

```
firma = hashlib.md5(datos).hexdigest()
```

## Ejemplo corregido

```
firma = hashlib.sha256(datos).hexdigest()
etag = hashlib.md5(datos, usedforsecurity=False).hexdigest()
```

## Referencias

- <https://docs.python.org/3/library/hashlib.html>
