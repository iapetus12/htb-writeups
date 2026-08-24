# HTB Writeups 🚩

Writeups de máquinas de [HackTheBox](https://www.hackthebox.com) resueltas en entornos de laboratorio autorizados, con fines educativos.

| Máquina | SO | Dificultad | user.txt | root.txt | Técnicas clave |
|---|---|---|---|---|---|
| [Nexus](nexus/) | Linux | Easy-Medium | `0f741c63...` | `80e617de...` | Git history leak · Password reuse · Unrestricted upload → RCE · Path traversal en timer systemd (root) |
| [Support](support/) | Windows (DC) | Medium | `fee57b2e...` | `8d441ff5...` | SMB anon share · .NET RE (XOR+0xDF) · LDAP info attr · WinRM · RBCD via GenericAll |

## Estructura

```
<maquina>/
├── writeup.md      # writeup completo: metodología, explotación, mitigaciones
└── scripts/        # herramientas desarrolladas durante el ataque
```

## Metodología general

1. **Recon**: escaneo completo de puertos + fingerprinting (`nmap`, TTL, banners)
2. **Enumeración**: servicios expuestos, vhosts, shares, LDAP/Kerberos según el objetivo
3. **Explotación**: manual primero — leer outputs, entender el porqué
4. **Post-explotación / escalada**: credenciales rotadas, ACLs, timers/crons, delegaciones
5. **Reporting**: vulnerabilidades clasificadas por CWE con mitigaciones

## Disclaimer

Todo el contenido es para uso educativo en laboratorios propios o plataformas autorizadas
(HTB, TryHackMe, VulnHub). No me hago responsable del mal uso de esta información.
