# Inyección de comandos (heurística)

`multi/command-injection` · severidad **crítica** · confianza medium · CWE-78 · OWASP A03:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

El comando se arma pegando texto (con `+`, `.` o `${}`) y se ejecuta con una shell. Con `;` o `&&` un atacante añade sus propios comandos.

## Cómo corregirlo

Usa APIs que reciben los argumentos como lista y no pasan por la shell: `execFile`/`spawn` en Node, `ProcessBuilder` en Java, `escapeshellarg()` como mínimo en PHP.

## Ejemplo vulnerable

```
child_process.exec("ls " + req.query.dir);
```

## Ejemplo corregido

```
child_process.execFile("ls", [req.query.dir]);
```

## Referencias

- (sin referencias)
