# Inyección SQL

`py/sql-injection` · severidad **crítica** · confianza high · CWE-89 · OWASP A03:2021

## Qué es y por qué es peligroso

La consulta SQL se construye pegando texto que viene del usuario. Un atacante puede cerrar la comilla y añadir su propio SQL (por ejemplo `' OR '1'='1`) para leer, modificar o borrar datos.

## Cómo corregirlo

Usa consultas parametrizadas: deja marcadores (`?` o `%s`) en el SQL y pasa los valores aparte, como segundo argumento de `execute()`. Nunca construyas SQL con `+`, `%`, f-strings ni `.format()`.

## Ejemplo vulnerable

```
uid = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = '%s'" % uid)
```

## Ejemplo corregido

```
uid = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
```

## Referencias

- <https://owasp.org/www-community/attacks/SQL_Injection>
- <https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html>
