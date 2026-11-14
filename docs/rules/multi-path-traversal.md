# Path traversal (heurística)

`multi/path-traversal` · severidad **alta** · confianza medium · CWE-22 · OWASP A01:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

Leer o servir un archivo cuyo nombre viene de la petición permite usar `../` para salir de la carpeta prevista y leer archivos del servidor.

## Cómo corregirlo

Normaliza con `path.basename()` / `basename()`, únelo a un directorio base y comprueba que la ruta resultante sigue dentro de él antes de abrirla.

## Ejemplo vulnerable

```
res.sendFile(req.query.file);
```

## Ejemplo corregido

```
res.sendFile(path.basename(req.query.file), { root: "/srv/files" });
```

## Referencias

- (sin referencias)
