# language: es
@CUS-04 @CUS-05
Característica: Cada usuario solo ve lo suyo
  Como estudiante
  Quiero que mis proyectos sean privados
  Para que nadie más vea mi código ni mis hallazgos

  Escenario: Otro estudiante no puede abrir mi proyecto
    Dado que soy un estudiante con sesión iniciada
    Y tengo un proyecto llamado "privado"
    Cuando otro estudiante intenta abrir mi proyecto
    Entonces recibe la respuesta "404"
    Y mi proyecto no aparece en su lista

  Escenario: Sin iniciar sesión no se accede a la API
    Cuando un visitante sin sesión pide la lista de proyectos
    Entonces recibe la respuesta "401"
