from pqc.kem import kyber512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

def generate_keys():
    try:
        pk, sk = kyber512.keypair()
        return base64.b64encode(pk).decode(), base64.b64encode(sk).decode()
    except Exception as e:
        print("Key generation error:", e)
        return None, None

def encrypt_message(message, pk_base64):
    try:
        pk = base64.b64decode(pk_base64)
        shared_secret, ciphertext = kyber512.encap(pk)
        return (
            base64.b64encode(ciphertext).decode(),
            base64.b64encode(shared_secret).decode()
        )
    except Exception as e:
        return f"Kyber Error: {e}", None

def decrypt_message(ciphertext_base64, sk_base64):
    try:
        ct = base64.b64decode(ciphertext_base64)
        sk = base64.b64decode(sk_base64)
        shared_secret = kyber512.decap(ct, sk)
        return base64.b64encode(shared_secret).decode()
    except Exception as e:
        return f"Kyber Error: {e}"

