# Deserialización insegura (heurística)

`multi/insecure-deserialization` · severidad **crítica** · confianza medium · CWE-502 · OWASP A08:2021

> Regla heurística (expresiones regulares): no analiza el flujo de datos.

## Qué es y por qué es peligroso

`unserialize()` en PHP, `ObjectInputStream` en Java, `BinaryFormatter` en .NET o `node-serialize` reconstruyen objetos con comportamiento; datos manipulados pueden ejecutar código.

## Cómo corregirlo

Intercambia datos en JSON y valídalos contra un esquema. En PHP usa `json_decode`; en Java, filtros de deserialización (`ObjectInputFilter`) o evita la serialización nativa.

## Ejemplo vulnerable

```
$obj = unserialize($_COOKIE["data"]);
```

## Ejemplo corregido

```
$obj = json_decode($_COOKIE["data"], true);
```

## Referencias

- (sin referencias)
