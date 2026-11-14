# Inyección SQL (heurística)

`multi/sql-injection` · severidad **crítica** · confianza medium · CWE-89 · OWASP A03:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

El texto de la consulta incluye valores pegados con `+`, `.` o `${}`. Si alguno viene del usuario, puede alterar la consulta y leer o borrar datos.

## Cómo corregirlo

Usa sentencias preparadas con marcadores (`?`, `$1`, `:id`) y pasa los valores aparte: `$pdo->prepare(...)->execute([$id])`, `db.query("... WHERE id = $1", [id])`, `PreparedStatement`.

## Ejemplo vulnerable

```
$r = query("SELECT * FROM users WHERE id = " . $id);
```

## Ejemplo corregido

```
$st = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$st->execute([$id]);
```

## Referencias

- (sin referencias)
