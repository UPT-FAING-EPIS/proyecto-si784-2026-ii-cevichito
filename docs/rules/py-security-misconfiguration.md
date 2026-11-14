# Configuración de seguridad insegura

`py/security-misconfiguration` · severidad **alta** · confianza high · CWE-295, CWE-489, CWE-942 · OWASP A05:2021

## Qué es y por qué es peligroso

Desactivar la verificación TLS permite que un intermediario lea o altere el tráfico; el modo debug de Flask expone una consola que ejecuta código; y CORS con `*` deja que cualquier web llame a tu API.

## Cómo corregirlo

Mantén `verify=True` (o pasa la ruta de tu CA), arranca en producción sin `debug=True` y limita CORS a una lista explícita de orígenes.

## Ejemplo vulnerable

```
requests.get(url, verify=False)
app.run(debug=True)
CORS(app, origins="*")
```

## Ejemplo corregido

```
requests.get(url, timeout=10)
app.run()
CORS(app, origins=["https://app.example.com"])
```

## Referencias

- <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
