#!/usr/bin/env python3
# deepwork: a local DNS filter that resolves only whitelisted sites while it is on.
import json
import os
import select
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

WIN = os.name == "nt"

USAGE = """Deep Work — focus mode for your machine.

While deepwork is on, only whitelisted sites and a few hardcoded lifeline
domains resolve; everything else gets an NXDOMAIN answer and won't load.

Usage:
  deepwork                  this help
  deepwork on               start focus mode (repoints the system resolver)
  deepwork off              stop focus mode and restore the resolver
  deepwork add <url>        allow a site (github.com, https://x.example/path, ...)
  deepwork remove <url>     take a site off the whitelist
  deepwork list             show the whitelist; lifeline domains are marked (locked)
  deepwork status           "on" or "off" plus the number of allowed sites

on and off need root (Linux) or administrator (Windows) rights and re-run
themselves with sudo/UAC when needed. Everything lives in ~/.config/deepwork
(Linux) or %APPDATA%\\deepwork (Windows): config.json is the whitelist you can
edit by hand, state.json tracks the running filter, blocked.log lists blocked
hostnames and daemon.log holds the filter's output."""


def _cfgdir():
    d = os.environ.get("DEEPWORK_DIR")
    if d:
        return d
    if WIN:
        return os.path.join(os.environ.get("APPDATA") or str(Path.home()), "deepwork")
    home = str(Path.home())
    u = os.environ.get("SUDO_USER")
    if u:  # re-run under sudo: keep the original user's config
        import pwd
        home = pwd.getpwnam(u).pw_dir
    x = os.environ.get("XDG_CONFIG_HOME")
    return os.path.join(x or os.path.join(home, ".config"), "deepwork")


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
            cfg = {**DEFAULTS, **json.load(f)}
        # entries typed by hand go through the same normalisation as 'deepwork
        # add', so a URL pasted straight into config.json works instead of
        # sitting there matching nothing
        cfg["sites"] = [s for s in map(norm, cfg["sites"]) if s]
        return cfg
    except (OSError, ValueError, TypeError, AttributeError):
        return dict(DEFAULTS)


def save(cfg):
    os.makedirs(DIR, exist_ok=True)
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    own(CFG)


def norm(s):
    # lowercase, drop scheme, query, fragment, path, port, a leading *. and www.
    s = s.lower().strip().split("://", 1)[-1]
    s = s.split("?", 1)[0].split("#", 1)[0].split("/", 1)[0]
    s = s.split(":", 1)[0].rstrip(".").removeprefix("*.").removeprefix("www.")
    return s if "." in s and " " not in s else ""


def add_site(url):
    s = norm(url)
    cfg = load()
    if not s:
        return "not a valid site"
    if s in cfg["sites"] or s in ALWAYS:
        return "already allowed"
    cfg["sites"].append(s)
    save(cfg)
    return "added " + s


def remove_site(url):
    s = norm(url)
    cfg = load()
    if s not in cfg["sites"]:
        return "not in the list"
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
        pass  # IPv6 is best effort

    cfg, mtime, logged = dict(DEFAULTS), None, set()

    def refresh():
        nonlocal cfg, mtime
        try:
            m = os.stat(cfgpath).st_mtime
            if m != mtime:
                with open(cfgpath, encoding="utf-8") as f:
                    c = {**DEFAULTS, **json.load(f)}
                c["sites"] = [s for s in map(norm, c["sites"]) if s]
                cfg, mtime = c, m  # swapped in together: a worker never sees a half-load
        except (OSError, ValueError, TypeError, AttributeError):
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

    def resolve(data, sites, upl):
        host, off = qname(data)
        if allowed(host, sites):
            return forward(data, ups or upl) or synth(data, off, 2)  # no upstream: SERVFAIL
        log_blocked(host)
        return synth(data, off, 3)  # NXDOMAIN

    def answer_udp(sock, data, addr, sites, upl):
        try:
            sock.sendto(resolve(data, sites, upl), addr)
        except Exception:
            pass  # one bad packet must never kill a worker

    def answer_tcp(conn, sites, upl):
        try:
            with conn:
                conn.settimeout(10)
                hdr = conn.recv(2)  # TCP framing: 2-byte big-endian length prefix
                if len(hdr) != 2:
                    return
                n = int.from_bytes(hdr, "big")
                q = b""
                while len(q) < n:
                    chunk = conn.recv(n - len(q))
                    if not chunk:
                        break
                    q += chunk
                if q:
                    reply = resolve(q, sites, upl)
                    conn.sendall(len(reply).to_bytes(2, "big") + reply)
        except Exception:
            pass  # a client that stalls must never hold up anyone else

    try:
        if os.path.getsize(LOG) > 32 * 1024:
            os.truncate(LOG, 0)
    except OSError:
        pass
    own(LOG)  # keep the log readable by the user, like the rest of the config dir

    # The loop must never block. forward() waits up to 2s per upstream, and doing
    # that inline stalls every other query behind it, blocked ones included: one
    # unresponsive upstream turned the whole filter into a queue. So the loop only
    # reads and hands off. refresh() stays here, where it is still single-threaded,
    # and the workers run on the snapshot it produced — no lock, no shared state.
    pool = ThreadPoolExecutor(max_workers=64)
    while True:
        for s in select.select(socks, [], [])[0]:
            try:
                refresh()  # config picked up here means an added site works on the next query
                sites, upl = cfg["sites"], cfg["upstream"]
                if s.type == socket.SOCK_STREAM:
                    conn, _ = s.accept()
                    pool.submit(answer_tcp, conn, sites, upl)
                else:
                    data, addr = s.recvfrom(4096)
                    pool.submit(answer_udp, s, data, addr, sites, upl)
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
        return [x for x in ups if x and not x.startswith("127.")]
    try:
        with open("/run/systemd/resolve/resolv.conf", encoding="utf-8") as f:
            ns = [l.split()[1] for l in f if l.startswith("nameserver ")]
    except OSError:
        return []
    # any loopback address would point the filter back at itself, directly or
    # through the resolved stub: never capture one as an upstream
    return [x for x in ns if not x.startswith("127.") and x != "::1"]


def _links():
    if WIN:
        ls = _pswin("").get("links") or []
        return ls if isinstance(ls, list) else [ls]
    ls = []
    for line in _run(["ip", "-o", "route", "show", "default"]).stdout.splitlines():
        try:
            dev = line.split(" dev ", 1)[1].split()[0]
        except IndexError:
            continue
        if dev not in ls:
            ls.append(dev)
    return ls


def _all_links():
    # every interface, so 'off' also finds a repointed link that is no longer a
    # default route, or that a stale state file no longer mentions
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def _link_config(link):
    # What the link hands out right now. 'resolvectl dns eno1' answers
    # "Link 2 (eno1): 1.2.3.4 5.6.7.8" and prints nothing after the colon when
    # the link has none, so everything past the first colon is the value.
    def value(cmd):
        out = _run(["resolvectl", cmd, link]).stdout
        return out.split(":", 1)[-1].split() if ":" in out else []
    return {"dns": value("dns"), "domain": value("domain")}


def _has_dns(link):
    # a link with no DNS server at all resolves nothing: that is the state 'off'
    # must never leave behind
    return bool(_link_config(link)["dns"])


def _loopback_dns(link):
    # True when the link still hands out the deepwork loopback resolver
    if WIN:
        out = _run(PS + [f"(Get-DnsClientServerAddress -InterfaceIndex {link} "
                         "-AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                         "Select-Object -ExpandProperty ServerAddresses) -join ' '"]).stdout.lower()
        return any(t in ("127.0.0.1", "::1") for t in out.split())
    return any(t in ("127.0.0.1", "::1") for t in _link_config(link)["dns"])


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


def dns_restore(links, saved=None):
    # Only links whose DNS still points at the deepwork loopback are touched, so
    # a hand-configured DNS server on an unrelated interface is never clobbered.
    # Every failure is verified and reported instead of being swallowed.
    saved = saved or {}
    bad = []
    if WIN:
        for i in links:
            if not _loopback_dns(i):
                continue
            _run(PS + [f"Set-DnsClientServerAddress -InterfaceIndex {i} -ResetServerAddresses"])
            if _loopback_dns(i):
                bad.append(str(i))
        _run(["ipconfig", "/flushdns"])
        return bad
    routed = _links()  # the links that actually carry traffic: those must end with DNS
    for link in links:
        if not _loopback_dns(link):
            continue
        if _run(["resolvectl", "revert", link]).returncode:
            _run(["resolvectl", "revert", link])  # one retry before giving up
        # revert is not a restore. It drops the link's whole runtime configuration,
        # including the servers NetworkManager pushed over D-Bus, and NM does not
        # push them again until the device is reactivated — so a plain revert used
        # to leave the machine with no resolver at all until the next reboot. Ask
        # NM to reapply, and if that does not bring DNS back, write down what the
        # link had before the switch.
        if not _has_dns(link):
            _run(["nmcli", "device", "reapply", link])
        was = saved.get(link) or {}
        if not _has_dns(link) and was.get("dns"):
            _run(["resolvectl", "dns", link] + was["dns"])
            if was.get("domain"):
                _run(["resolvectl", "domain", link] + was["domain"])
        if _loopback_dns(link) or (link in routed and not _has_dns(link)):
            bad.append(link)
    _run(["resolvectl", "flush-caches"])
    return bad


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
        # keep the file. If the filter died while the resolver was still repointed,
        # its links and their saved configuration are exactly what 'off' needs.
        return None
    return st


def probe():
    q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id + RD flag, QD=1
         + b"".join(bytes([len(p)]) + p.encode() for p in ALWAYS[0].split("."))
         + b"\x00\x00\x01\x00\x01")  # root label, qtype A, qclass IN
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
    # An empty capture — the link's DNS was wiped, or already points here — must
    # not start the filter with nothing to forward to: fall back to config.json.
    ups = upstream() or load()["upstream"]
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
    links = _links()
    if not links:
        daemon.terminate()
        return "could not repoint the system resolver, nothing was changed"
    # Record before switching: an interruption between these two moments must
    # still leave 'off' with the record it needs to undo the switch. That record
    # includes each link's own DNS configuration, because reverting the switch
    # does not bring it back on its own — see dns_restore.
    saved = {} if WIN else {l: _link_config(l) for l in links}
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump({"pid": daemon.pid, "links": links, "upstream": ups, "saved": saved}, f)
    own(STATE)
    if not dns_switch():
        off()
        return "could not repoint the system resolver, nothing was changed"
    try:
        socket.getaddrinfo(ALWAYS[0], 443)  # safety gate: the machine must still resolve
    except OSError:
        off()
        return "DNS broke after the switch; everything reverted"
    _autostart(True)
    return "on"


def off():
    # Read the state file directly, even when its daemon is dead: the recorded
    # links are the ground truth of what was repointed. The current default
    # routes and every interface are swept too, so a repointed link that state
    # lost track of (crash between switch and write, renamed interface, ...) is
    # still found. dns_restore only touches links with loopback DNS, so clean
    # interfaces and hand-configured DNS servers are left alone.
    try:
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = None
    links = list((st or {}).get("links") or [])
    for l in _links() + _all_links():
        if l not in links:
            links.append(l)
    bad = dns_restore(links, (st or {}).get("saved"))
    if st and st.get("pid"):
        try:
            os.kill(st["pid"], 15)
        except OSError:
            pass
    try:
        os.unlink(STATE)
    except OSError:
        pass
    _autostart(False)
    if bad:
        return ("off, but the DNS of " + ", ".join(bad) + " could not be restored"
                + "; fix with: sudo nmcli device reapply " + bad[0])
    return "off"


def status():
    n = len(load()["sites"])
    return ("on" if state() else "off") + f" · {n} sites"


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
        return USAGE
    cmd, *rest = a
    if cmd == "_daemon" and rest:  # the upstream list may be empty: config.json has one
        return serve(rest[0], rest[1:])
    if cmd in ("on", "off") and elevate():
        return None
    if cmd == "on":
        return on()
    if cmd == "off":
        return off()
    if cmd == "add" and rest:
        return add_site(rest[0])
    if cmd == "remove" and rest:
        return remove_site(rest[0])
    if cmd == "list":
        return "\n".join(load()["sites"] + [x + " (locked)" for x in ALWAYS])
    if cmd == "status":
        return status()
    print(USAGE)
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
