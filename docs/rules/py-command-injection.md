# Inyección de comandos del sistema

`py/command-injection` · severidad **crítica** · confianza high · CWE-78 · OWASP A03:2021

## Qué es y por qué es peligroso

El programa ejecuta un comando del sistema operativo construido con datos del usuario. Con caracteres como `;`, `&&` o `$(...)` el atacante encadena sus propios comandos en el servidor.

## Cómo corregirlo

Evita la shell: usa `subprocess.run([...])` con una lista de argumentos y `shell=False`. Si de verdad necesitas una cadena, escapa cada valor con `shlex.quote()` y valida contra una lista blanca.

## Ejemplo vulnerable

```
host = request.args.get("host")
os.system("ping -c 1 " + host)
```

## Ejemplo corregido

```
host = request.args.get("host")
subprocess.run(["ping", "-c", "1", host], check=True)
```

## Referencias

- <https://owasp.org/www-community/attacks/Command_Injection>
- <https://docs.python.org/3/library/subprocess.html#security-considerations>
