# criando a chave criptografada com o fernet da blbioteca cryptography

from cryptography.fernet import Fernet  # importa o modulo

key = Fernet.generate_key()  # gera um chave rangomica com base 64
print(key)
