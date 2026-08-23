#!/usr/bin/env python3
# deepwork: a local DNS filter that resolves only whitelisted sites while it is on.
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

WIN = os.name == "nt"
if WIN:
    import msvcrt
else:
    import termios
    import tty


def _cfgdir():
    d = os.environ.get("DEEPWORK_DIR")
    if d:
        return d
    if WIN:
        return os.path.join(os.environ.get("APPDATA") or str(Path.home()), "deepwork")
    x = os.environ.get("XDG_CONFIG_HOME")
    if x:
        return os.path.join(x, "deepwork")
    u = os.environ.get("SUDO_USER")
    home = str(Path.home())
    if u:
        import pwd
        home = pwd.getpwnam(u).pw_dir
    return os.path.join(home, ".config", "deepwork")


DIR = _cfgdir()
CFG = os.path.join(DIR, "config.json")
STATE = os.path.join(DIR, "state.json")
LOG = os.path.join(DIR, "blocked.log")
PORT = int(os.environ.get("DEEPWORK_PORT") or 53)
ALWAYS = ("anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
          "deepseek.com", "pi.dev")
LOCAL = (".lan", ".local", ".home.arpa", ".internal", ".in-addr.arpa", ".ip6.arpa")
DEFAULTS = {"sites": ["github.com", "stackoverflow.com", "python.org", "wikipedia.org"],
            "upstream": ["1.1.1.1", "8.8.8.8"]}


def own(path):
    if not WIN and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        import pwd
        pw = pwd.getpwnam(os.environ["SUDO_USER"])
        os.chown(path, pw.pw_uid, pw.pw_gid)


def load():
    try:
        with open(CFG, encoding="utf-8") as f:
            return {**DEFAULTS, **json.load(f)}
    except (OSError, ValueError):
        return dict(DEFAULTS)


def save(cfg):
    os.makedirs(DIR, exist_ok=True)
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    own(CFG)


def norm(s):
    s = s.lower().strip().split("://", 1)[-1]
    for c in "/?#":
        s = s.split(c, 1)[0]
    s = s.split(":", 1)[0].rstrip(".")
    if s.startswith("www."):
        s = s[4:]
    return s if "." in s and " " not in s else ""


def add_site(url):
    s = norm(url)
    cfg = load()
    if not s:
        return "!not a valid site"
    if s in cfg["sites"] or s in ALWAYS:
        return "!already allowed"
    cfg["sites"].append(s)
    save(cfg)
    return "added " + s


def remove_site(url):
    s = norm(url)
    cfg = load()
    if s not in cfg["sites"]:
        return "!not in the list"
    cfg["sites"].remove(s)
    save(cfg)
    return "removed " + s


def allowed(name, sites):
    name = name.lower().rstrip(".")
    if "." not in name or name.endswith(LOCAL):
        return True
    for e in sites + list(ALWAYS):
        if name == e or name.endswith("." + e):
            return True
    return False


def qname(pkt):
    # DNS labels: length byte + bytes per label, 0-terminated, starting at byte 12.
    parts = []
    i = 12
    while pkt[i]:
        n = pkt[i]
        i += 1
        parts.append(pkt[i:i + n].decode("latin-1"))
        i += n
    return ".".join(parts), i + 5  # past the 0 terminator and the 4 qtype/qclass bytes


def serve(cfgpath, ups):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", PORT))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", PORT))
    tcp.listen(16)
    socks = [udp, tcp]
    try:
        u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        u6.bind(("::1", PORT))
        t6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        t6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t6.bind(("::1", PORT))
        t6.listen(16)
        socks += [u6, t6]
    except OSError:
        pass

    cfg, mtime, logged = dict(DEFAULTS), None, set()

    def refresh():
        nonlocal cfg, mtime
        try:
            m = os.stat(cfgpath).st_mtime
            if m != mtime:
                with open(cfgpath, encoding="utf-8") as f:
                    cfg = {**DEFAULTS, **json.load(f)}
                mtime = m
        except (OSError, ValueError):
            pass

    def synth(pkt, off, rcode):
        # response flags + RCODE, zeroed counts, question echoed; drops any EDNS OPT
        return pkt[:2] + bytes([0x81, 0x80 | rcode]) + pkt[4:6] + b"\x00" * 6 + pkt[12:off]

    def log_blocked(host):
        if host not in logged:
            logged.add(host)
            try:
                with open(LOG, "a", encoding="utf-8") as f:
                    f.write(host + "\n")
            except OSError:
                pass

    def forward(query, ups):
        for u in ups:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(2)
                s.sendto(query, (u, 53))
                return s.recvfrom(4096)[0]
            except OSError:
                pass
            finally:
                s.close()

    def resolve(data):
        refresh()  # picking the config up here means an added site works on the very next query
        host, off = qname(data)
        if allowed(host, cfg["sites"]):
            return forward(data, ups or cfg["upstream"]) or synth(data, off, 2)  # no upstream: SERVFAIL
        log_blocked(host)
        return synth(data, off, 3)  # NXDOMAIN

    try:
        if os.path.getsize(LOG) > 32 * 1024:
            os.truncate(LOG, 0)
    except OSError:
        pass

    while True:
        for s in select.select(socks, [], [])[0]:
            try:
                if s.type == socket.SOCK_STREAM:
                    conn, _ = s.accept()
                    with conn:
                        conn.settimeout(10)
                        hdr = conn.recv(2)  # TCP framing: 2-byte big-endian length prefix
                        if len(hdr) == 2:
                            n = int.from_bytes(hdr, "big")
                            q = b""
                            while len(q) < n:
                                chunk = conn.recv(n - len(q))
                                if not chunk:
                                    break
                                q += chunk
                            if q:
                                reply = resolve(q)
                                conn.sendall(len(reply).to_bytes(2, "big") + reply)
                else:
                    data, addr = s.recvfrom(4096)
                    s.sendto(resolve(data), addr)
            except Exception:
                pass  # one bad packet must never kill the daemon


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


PS = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
PSWIN = ("$l=(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | "
         "Select-Object -ExpandProperty InterfaceIndex -Unique);"
         "$u=@();foreach($i in $l){$u+=(Get-DnsClientServerAddress "
         "-InterfaceIndex $i -AddressFamily IPv4).ServerAddresses};"
         "@{links=@($l);upstream=@($u)}|ConvertTo-Json -Compress;")


def _pswin(extra):
    try:
        return json.loads(_run(PS + [PSWIN + extra]).stdout)
    except ValueError:
        return {}


def upstream():
    if WIN:
        ups = _pswin("").get("upstream") or []
        if not isinstance(ups, list):
            ups = [ups]
        return [x for x in ups if x and x != "127.0.0.1"]
    try:
        with open("/run/systemd/resolve/resolv.conf", encoding="utf-8") as f:
            ns = [l.split()[1] for l in f if l.startswith("nameserver ")]
    except OSError:
        return []
    return [n for n in ns if n != "127.0.0.1"]


def _links():
    if WIN:
        ls = _pswin("").get("links") or []
        return ls if isinstance(ls, list) else [ls]
    ls = []
    for line in _run(["ip", "-o", "route", "show", "default"]).stdout.splitlines():
        parts = line.split()
        for i, t in enumerate(parts[:-1]):
            if t == "dev" and parts[i + 1] not in ls:
                ls.append(parts[i + 1])
    return ls


def dns_switch():
    if WIN:
        j = _pswin("foreach($i in $l){Set-DnsClientServerAddress -InterfaceIndex $i "
                   "-ServerAddresses ('127.0.0.1','::1')|Out-Null}")
        ls = j.get("links") or []
        return ls if isinstance(ls, list) else [ls]
    ls = []
    for link in _links():
        if _run(["resolvectl", "dns", link, "127.0.0.1"]).returncode == 0:
            _run(["resolvectl", "domain", link, "~."])
            ls.append(link)
    _run(["resolvectl", "flush-caches"])
    return ls


def dns_restore(links):
    if WIN:
        for i in links:
            _run(PS + [f"Set-DnsClientServerAddress -InterfaceIndex {i} -ResetServerAddresses"])
        _run(["ipconfig", "/flushdns"])
        return
    for link in links:
        _run(["resolvectl", "revert", link])
    _run(["resolvectl", "flush-caches"])


def alive(pid):
    if WIN:
        return str(pid) in _run(["tasklist", "/FI", f"PID eq {pid}"]).stdout
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True  # e.g. PermissionError: the process exists, we just cannot signal it


def state():
    try:
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        return None
    if not st.get("pid") or not alive(st["pid"]):
        try:
            os.unlink(STATE)
        except OSError:
            pass
        return None
    return st


def probe():
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id + RD flag, QD=1
    for part in ALWAYS[0].split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00\x00\x01\x00\x01"  # root label, qtype A, qclass IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(q, ("127.0.0.1", PORT))
        return bool(s.recvfrom(512))
    except OSError:
        return False
    finally:
        s.close()


def pyexe():
    # pythonw.exe runs the filter without leaving a console window open on Windows
    w = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return w if WIN and os.path.exists(w) else sys.executable


def _autostart(enable):
    # Windows Run key: ON must survive a reboot there; Linux DNS changes are runtime-only
    if not WIN:
        return
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Run",
                         0, winreg.KEY_SET_VALUE)
    if enable:
        winreg.SetValueEx(key, "deepwork", 0, winreg.REG_SZ,
                          f'"{pyexe()}" "{os.path.abspath(__file__)}" _daemon "{CFG}"')
    else:
        try:
            winreg.DeleteValue(key, "deepwork")
        except FileNotFoundError:
            pass
    winreg.CloseKey(key)


def _start_daemon(ups):
    os.makedirs(DIR, exist_ok=True)
    own(DIR)
    log = open(os.path.join(DIR, "daemon.log"), "ab")
    cmd = [pyexe(), os.path.abspath(__file__), "_daemon", CFG] + ups
    if WIN:
        p = subprocess.Popen(cmd, stdout=log, stderr=log,
                             creationflags=subprocess.DETACHED_PROCESS
                             | subprocess.CREATE_NO_WINDOW)
    else:
        p = subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True)
    log.close()
    own(os.path.join(DIR, "daemon.log"))
    return p


def wait_up(daemon):
    for _ in range(40):  # up to two seconds
        if daemon.poll() is not None:
            return False  # it died, usually because something already holds the port
        if probe():
            return True
        time.sleep(0.05)
    return False


def on():
    if state():
        return "already on"
    ups = upstream()
    daemon = _start_daemon(ups)
    if not wait_up(daemon):
        if daemon.poll() is None:
            daemon.terminate()
        try:
            with open(os.path.join(DIR, "daemon.log"), encoding="utf-8") as f:
                reason = f.read().strip().splitlines()[-1]
        except (OSError, IndexError):
            reason = "see " + os.path.join(DIR, "daemon.log")
        return "filter failed to start: " + reason
    links = dns_switch()
    if not links:
        daemon.terminate()
        return "could not repoint the system resolver, nothing was changed"
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump({"pid": daemon.pid, "links": links, "upstream": ups}, f)
    own(STATE)
    try:
        socket.getaddrinfo(ALWAYS[0], 443)  # safety gate: the machine must still resolve
    except OSError:
        off()
        return "DNS broke after the switch; everything reverted"
    _autostart(True)
    return "on"


def off():
    st = state()
    dns_restore((st or {}).get("links") or _links())
    if st:
        try:
            os.kill(st["pid"], 15)
        except OSError:
            pass
    try:
        os.unlink(STATE)
    except OSError:
        pass
    _autostart(False)
    return "off"


def status():
    n = len(load()["sites"])
    return ("on" if state() else "off") + f" · {n} sites"


# --- TUI ---
RESET = "\x1b[0m"
COL = {"t": "\x1b[38;2;238;246;255m", "m": "\x1b[38;2;155;179;209m",
       "a": "\x1b[1;38;2;88;169;255m", "b": "\x1b[38;2;53;109;166m",
       "w": "\x1b[38;2;139;200;255m", "s": "\x1b[38;2;54;139;214m",
       "r": "\x1b[38;2;255;107;107m"}  # text, muted, accent, border, wind, sea, alert
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if not COLOR:
    COL = {k: "" for k in COL}
    RESET = ""


def paint(lines):
    w = shutil.get_terminal_size().columns
    sys.stdout.write("\x1b[2J\x1b[H")
    for line in lines:
        pad = max(0, (w - len(re.sub(r"\x1b\[[0-9;]*m", "", line))) // 2)
        sys.stdout.write(" " * pad + line + RESET + "\n")
    sys.stdout.flush()


def key():
    if WIN:
        c = msvcrt.getwch()
        if c in "\xe0\x00":
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\n": "enter", "\x1b": "esc", "\x08": "back",
                "\x03": "esc"}.get(c, c)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        b = os.read(fd, 1)
        if not b:
            return "esc"  # stdin closed
        if b == b"\x1b":
            r, _, _ = select.select([fd], [], [], 0.1)  # arrows arrive as ESC [ A (or ESC O A)
            if r and os.read(fd, 1) in (b"[", b"O"):
                c = os.read(fd, 1)
                return "up" if c == b"A" else "down" if c == b"B" else ""
            return "esc"
        n = 1 + (b[0] >= 0xC0) + (b[0] >= 0xE0) + (b[0] >= 0xF0)  # finish a UTF-8 char
        while len(b) < n:
            b += os.read(fd, 1)
        c = b.decode(errors="replace")
        return {"\r": "enter", "\n": "enter", "\x7f": "back", "\x08": "back",
                "\x03": "esc"}.get(c, c)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def chrome(tagline):
    return [COL["w"] + "·╌╌╍━━╍╌·", COL["a"] + "▰  Deep Work  ▰", tagline]


def tagline():
    on = state() is not None
    c = COL["a"] if on else COL["m"]
    return c + ("on" if on else "off") + RESET + COL["m"] + \
        f" · {len(load()['sites'])} sites · dns filter"


def box(rows, marker_at=-1):
    h, v = ("─", "│") if COLOR else ("-", "|")
    c = ("╭", "╮", "╰", "╯") if COLOR else ("+",) * 4
    mk = "▸ " if COLOR else "> "
    out = [COL["b"] + c[0] + h * 50 + c[1]]
    for i, row in enumerate(rows):
        m = COL["a"] + mk if i == marker_at else "  "
        vis = len(re.sub(r"\x1b\[[0-9;]*m", "", row))
        out.append(COL["b"] + v + " " + m + row + " " * max(0, 46 - vis) + " " + COL["b"] + v)
    out.append(COL["b"] + c[2] + h * 50 + c[3])
    return out


def frame(box_lines, result="", keybar=None):
    lines = chrome(tagline()) + box_lines
    if result:
        colour = COL["r"] if result.startswith("!") else COL["m"]
        lines.append(colour + result.removeprefix("!") + RESET)
    lines.append(COL["m"] + (keybar or "↑↓ move · enter select · q quit") + RESET)
    lines.append(COL["s"] + "▁▂▃▄▅▆▇▆▅▄▃▂▁" + RESET)
    return lines


def enter_alt():
    sys.stdout.write("\x1b[?1049h\x1b[?25l")
    sys.stdout.flush()


def leave_alt():
    sys.stdout.write("\x1b[?1049l\x1b[?25h")
    sys.stdout.flush()


def toggle(on):
    leave_alt()
    subprocess.run([sys.executable, os.path.abspath(__file__), "off" if on else "on"])
    print(COL["m"] + "press any key to continue" + RESET, end="", flush=True)
    key()
    enter_alt()
    return ""


def recent_blocked():
    try:
        with open(LOG, encoding="utf-8") as f:
            hs = f.read().splitlines()
    except OSError:
        return []
    out = []
    for h in reversed(hs):  # most recent first, distinct, at most 8
        if h and h not in out:
            out.append(h)
            if len(out) == 8:
                break
    return out


def home():
    sel = 0
    result = ""
    while True:
        on = state() is not None
        rows = [(("Turn off", "stop focus mode") if on else ("Turn on", "start focus mode")),
                ("Add site", "allow one more"),
                ("Remove site", f"{len(load()['sites'])} in the list"),
                ("Quit", "")]
        paint(frame(box([COL["t"] + a.ljust(16) + COL["m"] + b for a, b in rows], sel), result))
        k = key()
        if k in ("q", "esc"):
            return
        if k == "up":
            sel = (sel - 1) % 4
        elif k == "down":
            sel = (sel + 1) % 4
        elif k == "enter":
            if sel == 0:
                result = toggle(on)
            elif sel == 1:
                result = add_screen()
            elif sel == 2:
                result = remove_screen()
            else:
                return


def add_screen():
    inp = ""
    result = ""
    while True:
        sugs = recent_blocked()
        rows = [COL["m"] + "site to allow", COL["t"] + (inp or "type a domain")]
        if sugs:
            rows += [""] + [COL["m"] + f"{i+1} {h[:40]}" for i, h in enumerate(sugs)]
        paint(frame(box(rows, 1), result, "type · enter add · esc cancel"))
        k = key()
        if k == "esc":
            return result
        if k == "back":
            inp = inp[:-1]
        elif k == "enter":
            s = norm(inp)
            cfg = load()
            if not s:
                result = "!not a valid site"
            elif s in cfg["sites"] or s in ALWAYS:
                result = "!already allowed"
            else:
                cfg["sites"].append(s)
                save(cfg)
                result = "added " + s
                inp = ""
        elif not inp and k in "12345678" and int(k) <= len(sugs):
            inp = sugs[int(k) - 1]
        elif len(k) == 1 and k.isprintable() and len(inp) < 40:
            inp += k


def remove_screen():
    sel = 0
    result = ""
    while True:
        sites = [s for s in load()["sites"] if s not in ALWAYS]
        if not sites:
            paint(frame(box([COL["m"] + "nothing to remove".center(46)], -1), result, "esc back"))
            if key() == "esc":
                return result
            continue
        sel = min(sel, len(sites) - 1)
        paint(frame(box([COL["t"] + s[:44] for s in sites], sel), result,
                    "↑↓ move · enter remove · esc back"))
        k = key()
        if k == "esc":
            return result
        if k == "up":
            sel = (sel - 1) % len(sites)
        elif k == "down":
            sel = (sel + 1) % len(sites)
        elif k == "enter":
            result = remove_site(sites[sel])


def tui():
    try:
        enter_alt()
        home()
    except KeyboardInterrupt:
        pass
    finally:
        leave_alt()


def elevate():
    # re-run as root (Linux) or administrator (Windows): on/off touch the system resolver
    if WIN:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return False
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return True  # the elevated copy does the work; the caller exits quietly
    if os.geteuid():
        os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(__file__)] + sys.argv[1:])
    return False


def main():
    a = sys.argv[1:]
    if not a:
        return tui()
    if a[0] in ("on", "off"):
        if elevate():
            return None
        return on() if a[0] == "on" else off()
    if a[0] == "_daemon" and len(a) > 1:
        return serve(a[1], a[2:])
    if a[0] == "add" and len(a) > 1:
        return add_site(a[1]).removeprefix("!")
    if a[0] == "remove" and len(a) > 1:
        return remove_site(a[1]).removeprefix("!")
    if a[0] == "list":
        return "\n".join(load()["sites"] + [x + " (locked)" for x in ALWAYS])
    if a[0] == "status":
        return status()
    print("usage: deepwork [on|off|add <site>|remove <site>|list|status]")
    print("       deepwork                 the interactive menu")
    sys.exit(2)


if __name__ == "__main__":
    try:
        r = main()
        if r is not None:
            print(r)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print("deepwork: " + str(e), file=sys.stderr)
        sys.exit(1)
