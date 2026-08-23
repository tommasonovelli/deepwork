#!/usr/bin/env python3
# deepwork installer: clean-installs into PREFIX; uninstall keeps your config.
import os, shutil, subprocess, sys
from pathlib import Path

if sys.version_info < (3, 12):
    sys.exit("deepwork installer: Python 3.12 or newer is required")
import deepwork  # sibling, for deepwork.DIR: the config dir this installer never touches

WIN = os.name == "nt"
if WIN:
    import ctypes
    import winreg

def prefix():
    return os.path.abspath(os.environ.get("DEEPWORK_PREFIX") or (
        "/usr/local" if not WIN else os.path.join(
            os.environ.get("LOCALAPPDATA") or str(Path.home()), "Programs")))

def elevate():
    # re-exec through sudo only when the shim dir is not writable by this user
    if WIN:
        return
    b = Path(prefix()) / "bin"
    # probe the nearest existing parent: creating a probe file here would create
    # the very directory the probe is meant to test
    probe = b
    while not probe.exists():
        probe = probe.parent
    if not os.access(probe, os.W_OK):
        # sudo strips most env vars; re-export the ones that decide where we install
        env = [f"{v}={os.environ[v]}" for v in ("DEEPWORK_PREFIX", "DEEPWORK_DIR") if v in os.environ]
        os.execvp("sudo", ["sudo", *env, sys.executable, os.path.abspath(__file__), *sys.argv[1:]])

def edit_path(d, add):
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                       winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)
    try:
        val, typ = winreg.QueryValueEx(k, "Path")
    except FileNotFoundError:
        val, typ = "", winreg.REG_EXPAND_SZ
    parts = [p for p in (val or "").split(";") if p and p.lower() != d.lower()]
    if add:
        parts.append(d)
    winreg.SetValueEx(k, "Path", 0, typ, ";".join(parts))
    winreg.CloseKey(k)
    # broadcast so Explorer and new shells pick the PATH change up
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 2, 5000, None)

def install():
    elevate()
    dst = Path(prefix()) / ("deepwork" if WIN else os.path.join("lib", "deepwork"))
    shutil.rmtree(dst, ignore_errors=True)  # clean install: stale files never survive
    dst.mkdir(parents=True)
    shutil.copy2(Path(__file__).parent / "deepwork.py", dst / "deepwork.py")
    if WIN:
        cmd = f'@echo off\r\n"{sys.executable}" "%~dp0deepwork.py" %*\r\n'
        (dst / "deepwork.cmd").write_bytes(cmd.encode())
        edit_path(str(dst), True)
        print(f"installed {dst / 'deepwork.py'} and added {dst} to the user PATH")
    else:
        shim = Path(prefix()) / "bin" / "deepwork"
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text(f'#!/bin/sh\nexec python3 {dst / "deepwork.py"} "$@"\n')
        shim.chmod(0o755)
        print(f"installed {dst / 'deepwork.py'} with command shim at {shim}")
    print("next: open a new terminal and run: deepwork")

def uninstall():
    elevate()
    dst = Path(prefix()) / ("deepwork" if WIN else os.path.join("lib", "deepwork"))
    # Undo the resolver switch before the filter's file disappears. repointed()
    # rather than state(): state() goes None once the pid is dead, and a dead
    # filter with the resolver still aimed at it is the case that matters most.
    # It also stays False on a machine that was never on, so an ordinary
    # uninstall does not demand root just to ask.
    if deepwork.repointed():
        script = dst / "deepwork.py"
        if not script.exists():
            script = Path(deepwork.__file__)
        # no capture: the off subprocess may re-exec through sudo, whose password
        # prompt must reach the terminal; off prints its own result either way
        if subprocess.run([sys.executable, str(script), "off"]).returncode:
            # removing deepwork.py now would take away the command that fixes DNS
            sys.exit("deepwork installer: off failed; nothing was removed\n"
                     "run: sudo deepwork off first")
    if WIN:
        edit_path(str(dst), False)
        deepwork._autostart(False)
        print("removed the PATH entry and the autostart Run key")
    shutil.rmtree(dst, ignore_errors=True)
    if not WIN:
        Path(prefix()).joinpath("bin", "deepwork").unlink(missing_ok=True)
    print(f"removed the installed files\nconfig kept at {deepwork.DIR}")

if __name__ == "__main__":
    try:
        if sys.argv[1:] not in ([], ["uninstall"]):
            print("usage: python3 installer.py [uninstall]")
            sys.exit(1)
        sys.exit(uninstall() if sys.argv[1:] else install())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.exit("deepwork installer: " + str(e))
