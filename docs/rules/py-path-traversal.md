# Path traversal (acceso a rutas arbitrarias)

`py/path-traversal` · severidad **alta** · confianza high · CWE-22 · OWASP A01:2021

## Qué es y por qué es peligroso

El nombre de archivo viene del usuario y se usa tal cual. Con `../` el atacante sale de la carpeta prevista y lee o borra archivos del servidor, como `/etc/passwd` o la configuración con secretos.

## Cómo corregirlo

Reduce el nombre a su parte final con `os.path.basename()` o `secure_filename()`, únelo a un directorio base y comprueba con `os.path.realpath()` que el resultado sigue dentro de ese directorio.

## Ejemplo vulnerable

```
name = request.args.get("f")
return open("/srv/files/" + name).read()
```

## Ejemplo corregido

```
name = secure_filename(request.args.get("f"))
return send_from_directory("/srv/files", name)
```

## Referencias

- <https://owasp.org/www-community/attacks/Path_Traversal>
