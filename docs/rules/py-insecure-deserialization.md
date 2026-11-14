# Deserialización insegura

`py/insecure-deserialization` · severidad **crítica** · confianza high · CWE-502 · OWASP A08:2021

## Qué es y por qué es peligroso

`pickle`, `marshal`, `shelve` o `yaml.load` sin cargador seguro reconstruyen objetos arbitrarios. Un archivo o mensaje preparado por un atacante ejecuta código en el servidor al cargarse.

## Cómo corregirlo

Para datos externos usa formatos sin código: JSON (`json.loads`) o YAML con `yaml.safe_load()`. Usa `pickle` solo con datos que tu propio sistema generó y firmó.

## Ejemplo vulnerable

```
datos = pickle.loads(request.data)
cfg = yaml.load(texto)
```

## Ejemplo corregido

```
datos = json.loads(request.data)
cfg = yaml.safe_load(texto)
```

## Referencias

- <https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html>
