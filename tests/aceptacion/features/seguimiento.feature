# language: es
@CUS-16 @CUS-17
Característica: Medir el progreso entre escaneos
  Como estudiante
  Quiero volver a analizar mi código después de corregirlo
  Para comprobar que el fallo desaparece y que mis decisiones se conservan

  Antecedentes:
    Dado que soy un estudiante con sesión iniciada
    Y tengo un proyecto llamado "tarea-progreso"

  Escenario: Corregir el fallo lo marca como corregido
    Dado que analicé el código "vulnerable"
    Cuando analizo el código "corregido"
    Entonces la comparación con el escaneo anterior muestra "py/sql-injection" como corregido

  Escenario: Un falso positivo sigue marcado al volver a escanear
    Dado que analicé el código "vulnerable"
    Y marqué el hallazgo "py/sql-injection" como "false_positive" con la justificación "Es un ejemplo de clase"
    Cuando analizo el código "vulnerable con una línea más"
    Entonces el hallazgo "py/sql-injection" sigue marcado como "false_positive"
