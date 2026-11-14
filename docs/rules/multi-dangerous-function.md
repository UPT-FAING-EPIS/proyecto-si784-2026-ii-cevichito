# Ejecución dinámica de código (heurística)

`multi/dangerous-function` · severidad **alta** · confianza medium · CWE-95 · OWASP A03:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

`eval()` o `new Function()` convierten texto en código. Si el texto puede venir del usuario, el atacante ejecuta lo que quiera en el navegador o en el servidor.

## Cómo corregirlo

Usa `JSON.parse()` para datos y una tabla de funciones permitidas para elegir comportamientos.

## Ejemplo vulnerable

```
const r = eval(req.body.expr);
```

## Ejemplo corregido

```
const datos = JSON.parse(req.body.json);
```

## Referencias

- (sin referencias)
