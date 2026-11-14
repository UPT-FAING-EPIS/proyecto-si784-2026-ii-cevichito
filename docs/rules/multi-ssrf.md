# SSRF (heurística)

`multi/ssrf` · severidad **alta** · confianza medium · CWE-918 · OWASP A10:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

Si el usuario elige la URL a la que llama el servidor, puede apuntar a servicios internos o a los metadatos de la nube.

## Cómo corregirlo

Construye la URL en el servidor a partir de un identificador, o valida esquema y host contra una lista blanca antes de llamar.

## Ejemplo vulnerable

```
const r = await fetch(req.query.url);
```

## Ejemplo corregido

```
const r = await fetch(SERVICIOS[req.query.svc]);
```

## Referencias

- (sin referencias)
