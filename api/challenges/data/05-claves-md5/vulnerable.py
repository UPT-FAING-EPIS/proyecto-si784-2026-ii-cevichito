import hashlib

USUARIOS = {}


def registrar(usuario, clave):
    USUARIOS[usuario] = hashlib.md5(clave.encode()).hexdigest()


def verificar(usuario, clave):
    return USUARIOS.get(usuario) == hashlib.md5(clave.encode()).hexdigest()
