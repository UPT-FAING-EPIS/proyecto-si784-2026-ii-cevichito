# Aleatoriedad predecible

`py/insecure-random` · severidad **baja** · confianza low · CWE-330, CWE-338 · OWASP A02:2021

## Qué es y por qué es peligroso

El módulo `random` usa un generador determinista (Mersenne Twister): observando algunas salidas se pueden predecir las siguientes. Es adecuado para simulaciones, no para tokens, contraseñas ni códigos.

## Cómo corregirlo

Para cualquier valor que deba ser secreto usa `secrets.token_urlsafe()`, `secrets.token_hex()` o `secrets.randbelow()`. Si el uso no es de seguridad, puedes suprimir el hallazgo con un motivo.

## Ejemplo vulnerable

```
codigo = random.randint(100000, 999999)
```

## Ejemplo corregido

```
codigo = secrets.randbelow(900000) + 100000
```

## Referencias

- <https://docs.python.org/3/library/secrets.html>
