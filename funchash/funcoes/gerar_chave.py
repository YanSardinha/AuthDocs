from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import os

def gera_chaves():
  def gera_chaves_hash():
    seed = os.urandom(16)  # Gere uma semente aleatória
    chave_privada = hashlib.sha256(seed).digest()
    chave_publica = hashlib.sha256(chave_privada).digest()

    return {
        'chave_publica': chave_publica.hex(),
        'chave_privada': chave_privada.hex()
    }

 
'''  
 UTILIZANDO RSA (MECANISMOS MAIS SEGUROS)
 
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    chave_privada_bytes = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    chave_publica = chave_privada.public_key()

    chave_publica_bytes = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        'chave_publica': chave_publica_bytes.decode('utf-8'),
        'chave_privada': chave_privada_bytes.decode('utf-8')
    }
''' 