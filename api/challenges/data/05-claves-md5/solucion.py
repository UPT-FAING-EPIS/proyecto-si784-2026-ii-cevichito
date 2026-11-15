from werkzeug.security import check_password_hash, generate_password_hash

USUARIOS = {}


def registrar(usuario, clave):
    USUARIOS[usuario] = generate_password_hash(clave)


def verificar(usuario, clave):
    huella = USUARIOS.get(usuario)
    return huella is not None and check_password_hash(huella, clave)
