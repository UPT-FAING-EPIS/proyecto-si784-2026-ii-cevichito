# language: es
@CUS-07 @CUS-13
Característica: Analizar código pegado y entender el hallazgo
  Como estudiante que aprende seguridad
  Quiero analizar mi código y leer qué fallo tiene
  Para saber por qué es peligroso y cómo corregirlo

  Antecedentes:
    Dado que soy un estudiante con sesión iniciada
    Y tengo un proyecto llamado "tarea-login"

  Escenario: Se detecta una inyección SQL y se explica
    Cuando analizo el código "vulnerable"
    Entonces el escaneo termina correctamente
    Y aparece un hallazgo de la regla "py/sql-injection" con severidad "critical"
    Y el hallazgo trae su explicación, su corrección y el CWE "CWE-89"

  Escenario: El código seguro no tiene hallazgos graves
    Cuando analizo el código "corregido"
    Entonces el escaneo termina correctamente
    Y no aparece ningún hallazgo de la regla "py/sql-injection"
