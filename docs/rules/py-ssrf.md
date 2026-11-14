# Server-Side Request Forgery (SSRF)

`py/ssrf` · severidad **alta** · confianza high · CWE-918 · OWASP A10:2021

## Qué es y por qué es peligroso

El servidor hace una petición HTTP a una URL que elige el usuario. El atacante puede apuntar a servicios internos (`http://localhost:...`, `169.254.169.254` en la nube) que no deberían ser accesibles.

## Cómo corregirlo

No aceptes URLs completas del usuario: acepta un identificador y construye la URL en el servidor, o valida el esquema y el host contra una lista blanca antes de hacer la petición.

## Ejemplo vulnerable

```
url = request.args.get("url")
return requests.get(url).text
```

## Ejemplo corregido

```
ALLOWED = {"status": "https://api.example.com/status"}
return requests.get(ALLOWED[request.args["svc"]], timeout=5).text
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
