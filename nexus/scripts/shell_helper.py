import pty, os, time, sys
def run(cmds, user="jones", pw="y27xb3ha!!74GbR", host="10.129.107.139"):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("ssh", ["ssh","-o","StrictHostKeyChecking=no","-o","PreferredAuthentications=password",
                          "-o","PubkeyAuthentication=no","-o","NumberOfPasswordPrompts=1",f"{user}@{host}",cmds])
    out, sent = b"", False
    end = time.time() + 25
    while time.time() < end:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        out += d
        if not sent and b"password:" in out.lower():
            os.write(fd, pw.encode()+b"\n"); sent = True
        if sent and os.waitpid(pid, os.WNOHANG)[0] != 0: break
    try: os.close(fd)
    except: pass
    return out.decode(errors="replace")
print(run(sys.argv[1]))
