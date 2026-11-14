# Cross-Site Scripting (XSS)

`py/xss` · severidad **alta** · confianza high · CWE-79 · OWASP A03:2021

## Qué es y por qué es peligroso

Texto del usuario se inserta en una página HTML sin escapar. Si contiene `<script>`, el navegador de otra persona lo ejecuta y el atacante puede robar su sesión o actuar en su nombre.

## Cómo corregirlo

Usa `render_template()` con plantillas Jinja2 (escapan por defecto) en lugar de `render_template_string()` con texto concatenado. Si debes construir HTML, aplica `html.escape()`.

## Ejemplo vulnerable

```
name = request.args.get("n")
return render_template_string("<h1>Hola " + name + "</h1>")
```

## Ejemplo corregido

```
name = request.args.get("n")
return render_template("saludo.html", name=name)
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
