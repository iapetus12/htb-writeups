#!/usr/bin/env python3
"""Recupera credenciales cifradas de UserInfo.exe (Support - HTB).
Algoritmo extraído por desensamblado IL: plain = XOR(cipher, key) XOR 0xDF"""
import base64
import sys

ENC_PASSWORD = '0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'
KEY = b'armando'

def decrypt(enc_b64: str, key: bytes = KEY) -> str:
    data = base64.b64decode(enc_b64)
    return bytes(b ^ key[i % len(key)] ^ 0xDF for i, b in enumerate(data)).decode()

if __name__ == '__main__':
    enc = sys.argv[1] if len(sys.argv) > 1 else ENC_PASSWORD
    print(f'[+] support\\ldap : {decrypt(enc)}')
