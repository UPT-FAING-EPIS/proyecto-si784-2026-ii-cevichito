# Catálogo de reglas

| ID | Nombre | Severidad | Motor |
|---|---|---|---|
| [`generic/hardcoded-secret`](generic-hardcoded-secret.md) | Secreto escrito en el código | alta | ast |
| [`multi/command-injection`](multi-command-injection.md) | Inyección de comandos (heurística) | crítica | heuristic |
| [`multi/dangerous-function`](multi-dangerous-function.md) | Ejecución dinámica de código (heurística) | alta | heuristic |
| [`multi/insecure-deserialization`](multi-insecure-deserialization.md) | Deserialización insegura (heurística) | crítica | heuristic |
| [`multi/path-traversal`](multi-path-traversal.md) | Path traversal (heurística) | alta | heuristic |
| [`multi/sql-injection`](multi-sql-injection.md) | Inyección SQL (heurística) | crítica | heuristic |
| [`multi/ssrf`](multi-ssrf.md) | SSRF (heurística) | alta | heuristic |
| [`multi/weak-hash`](multi-weak-hash.md) | Hash criptográfico débil (heurística) | media | heuristic |
| [`multi/xss`](multi-xss.md) | Cross-Site Scripting (heurística) | alta | heuristic |
| [`py/command-injection`](py-command-injection.md) | Inyección de comandos del sistema | crítica | taint |
| [`py/dangerous-function`](py-dangerous-function.md) | Ejecución dinámica de código | alta | ast |
| [`py/insecure-deserialization`](py-insecure-deserialization.md) | Deserialización insegura | crítica | ast |
| [`py/insecure-password-hash`](py-insecure-password-hash.md) | Contraseña guardada con un hash rápido | alta | ast |
| [`py/insecure-random`](py-insecure-random.md) | Aleatoriedad predecible | baja | ast |
| [`py/jwt-weakness`](py-jwt-weakness.md) | Validación insegura de JWT | alta | ast |
| [`py/path-traversal`](py-path-traversal.md) | Path traversal (acceso a rutas arbitrarias) | alta | taint |
| [`py/security-misconfiguration`](py-security-misconfiguration.md) | Configuración de seguridad insegura | alta | ast |
| [`py/sql-injection`](py-sql-injection.md) | Inyección SQL | crítica | taint |
| [`py/ssrf`](py-ssrf.md) | Server-Side Request Forgery (SSRF) | alta | taint |
| [`py/weak-cipher`](py-weak-cipher.md) | Cifrado débil u obsoleto | alta | ast |
| [`py/weak-hash`](py-weak-hash.md) | Hash criptográfico débil | media | ast |
| [`py/xss`](py-xss.md) | Cross-Site Scripting (XSS) | alta | taint |
