# Secreto escrito en el código

`generic/hardcoded-secret` · severidad **alta** · confianza medium · CWE-798 · OWASP A07:2021

## Qué es y por qué es peligroso

Una contraseña, token o clave aparece literalmente en el código. Cualquiera con acceso al repositorio (o a una copia filtrada) la obtiene, y cambiarla exige modificar y redesplegar el código.

## Cómo corregirlo

Lee el secreto del entorno (`os.environ["API_KEY"]`) o de un gestor de secretos, sin valor por defecto: si falta, la aplicación no debe arrancar. Revoca el secreto expuesto, porque sigue en el historial.

## Ejemplo vulnerable

```
API_KEY = "sk-live-abcdef1234567890abcdef"
SECRET = os.environ.get("SECRET", "clave-por-defecto")
```

## Ejemplo corregido

```
API_KEY = os.environ["API_KEY"]
SECRET = os.environ["SECRET"]  # sin valor por defecto
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
