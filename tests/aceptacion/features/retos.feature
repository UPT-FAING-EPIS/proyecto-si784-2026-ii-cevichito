# language: es
@CUS-26 @CUS-27 @CUS-28
Característica: Retos de corrección
  Como estudiante
  Quiero corregir código vulnerable preparado
  Para practicar y que el sistema compruebe si lo corregí de verdad

  Antecedentes:
    Dado que soy un estudiante con sesión iniciada

  Esquema del escenario: Cada reto se supera con una corrección real
    Cuando envío el código de partida del reto "<reto>"
    Entonces el veredicto es "sigue"
    Cuando envío la solución del reto "<reto>"
    Entonces el veredicto es "superado"
    Y el reto "<reto>" aparece como superado en la lista

    Ejemplos:
      | reto                   |
      | 01-login-sql           |
      | 02-ping-comandos       |
      | 03-descargas-ruta      |
      | 04-saludo-xss          |
      | 05-claves-md5          |
      | 06-token-en-codigo     |
      | 07-calculadora-eval    |
      | 08-preferencias-pickle |

  Escenario: Silenciar el aviso no cuenta como corregir
    Cuando envío el código de partida del reto "01-login-sql" silenciado con "# nosec"
    Entonces el veredicto es "silenciado"

  Escenario: Borrar el código no cuenta como corregir
    Cuando envío un código sin las funciones del reto "01-login-sql"
    Entonces el envío se rechaza con el error "missing_functions"

  Escenario: Vaciar la función del reto tampoco cuenta como corregir
    Cuando envío el código "def login(): return 'ok'" al reto "01-login-sql"
    Entonces el envío se rechaza con el error "behavior_missing"

  Escenario: Un código con errores de sintaxis se rechaza sin analizarlo
    Cuando envío el código "def login(:" al reto "01-login-sql"
    Entonces el envío se rechaza con el error "syntax_error"
