#!/bin/bash
IP="10.129.107.139"
JAR=/tmp/opencode/cookies.txt; rm -f $JAR
EMAIL="$1"; PASS="$2"

# 1) Obtener página de login (cookie de sesión + token CSRF)
TOKEN=$(curl -s --resolve billing.nexus.htb:80:$IP -c $JAR http://billing.nexus.htb/admin/login | grep -oP 'name="_token" value="\K[^"]+' | head -1)
[ -z "$TOKEN" ] && { echo "[!] No pude obtener _token"; exit 1; }

# 2) Enviar credenciales
HTTP=$(curl -s --resolve billing.nexus.htb:80:$IP -b $JAR -c $JAR \
  -o /tmp/opencode/login_resp.html -w "%{http_code}|%{redirect_url}" \
  -d "_token=$TOKEN&email=$EMAIL&password=$PASS" \
  http://billing.nexus.htb/admin/login)

echo "[*] Respuesta: $HTTP"
grep -qiE "dashboard|welcome|sign out|logout" /tmp/opencode/login_resp.html && echo "[+] LOGIN VÁLIDO ✅" || echo "[-] Login rechazado"
