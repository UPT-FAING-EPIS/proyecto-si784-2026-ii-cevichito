# Ejecución dinámica de código

`py/dangerous-function` · severidad **alta** · confianza medium · CWE-95 · OWASP A03:2021

## Qué es y por qué es peligroso

`eval()`, `exec()` y `compile()` ejecutan texto como código Python. Si ese texto puede venir, aunque sea en parte, del usuario, el atacante ejecuta lo que quiera con los permisos de la aplicación.

## Cómo corregirlo

Para leer literales usa `ast.literal_eval()`; para configuraciones, JSON o YAML seguro; para elegir una operación, un diccionario de funciones permitidas en lugar de construir código.

## Ejemplo vulnerable

```
resultado = eval(request.args["expr"])
```

## Ejemplo corregido

```
valores = ast.literal_eval(texto)
```

## Referencias

- <https://docs.python.org/3/library/functions.html#eval>
