# Cross-Site Scripting (heurística)

`multi/xss` · severidad **alta** · confianza low · CWE-79 · OWASP A03:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

Asignar a `innerHTML`, usar `document.write`, `dangerouslySetInnerHTML`, `v-html` o imprimir un parámetro en PHP sin escapar convierte texto del usuario en HTML ejecutable en el navegador de otra persona.

## Cómo corregirlo

Usa `textContent` para texto plano, deja que React o Vue escapen por defecto, y en PHP aplica `htmlspecialchars($valor, ENT_QUOTES, 'UTF-8')`. Si necesitas HTML, sanéalo con DOMPurify.

## Ejemplo vulnerable

```
el.innerHTML = params.get("q");
```

## Ejemplo corregido

```
el.textContent = params.get("q");
```

## Referencias

- (sin referencias)
