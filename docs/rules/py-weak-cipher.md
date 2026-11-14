# Cifrado débil u obsoleto

`py/weak-cipher` · severidad **alta** · confianza high · CWE-327 · OWASP A02:2021

## Qué es y por qué es peligroso

DES, 3DES, RC4 o Blowfish tienen claves cortas o debilidades conocidas, y el modo ECB cifra igual los bloques iguales, así que deja ver patrones del mensaje. Un atacante puede descifrar o manipular datos.

## Cómo corregirlo

Usa un cifrado autenticado moderno: AES en modo GCM (`AES.new(key, AES.MODE_GCM)`) o `cryptography.fernet.Fernet`, con claves de 256 bits generadas con `secrets`.

## Ejemplo vulnerable

```
cipher = DES.new(key, DES.MODE_ECB)
```

## Ejemplo corregido

```
cipher = AES.new(key, AES.MODE_GCM)
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
