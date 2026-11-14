# Validación insegura de JWT

`py/jwt-weakness` · severidad **alta** · confianza high · CWE-347 · OWASP A07:2021

## Qué es y por qué es peligroso

Si no se verifica la firma, o se acepta el algoritmo `none`, cualquiera puede fabricar un token con el usuario o los permisos que quiera, y la aplicación lo dará por bueno.

## Cómo corregirlo

Llama a `jwt.decode(token, clave, algorithms=["HS256"])` fijando la lista de algoritmos y sin desactivar `verify_signature`. Nunca incluyas `none` entre los algoritmos permitidos.

## Ejemplo vulnerable

```
jwt.decode(token, options={"verify_signature": False})
```

## Ejemplo corregido

```
jwt.decode(token, SECRET, algorithms=["HS256"])
```

## Referencias

- <https://datatracker.ietf.org/doc/html/rfc8725>
