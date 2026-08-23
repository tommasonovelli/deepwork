#!/usr/bin/env python3
# deepwork uninstaller: the complete reverse of installer.py. Removes the
# installed files, the `deepwork` command (and on Windows the PATH entry and
# the autostart Run key) and the config directory — nothing is left behind.
# Unlike `installer.py uninstall`, which keeps your config, this is for
# walking away entirely.
import os, shutil, subprocess, sys
from pathlib import Path

if sys.version_info < (3, 12):
    sys.exit("deepwork uninstaller: Python 3.12 or newer is required")
import deepwork  # sibling, for deepwork.DIR: the config directory this tool removes

WIN = os.name == "nt"
if WIN:
    import ctypes
    import winreg


def prefix():
    # same rule as installer.py: a DEEPWORK_PREFIX installs/uninstalls elsewhere
    return os.path.abspath(os.environ.get("DEEPWORK_PREFIX") or (
        "/usr/local" if not WIN else os.path.join(
            os.environ.get("LOCALAPPDATA") or str(Path.home()), "Programs")))


def elevate():
    # re-exec through sudo only when the shim dir is not writable by this user
    if WIN:
        return
    b = Path(prefix()) / "bin"
    try:
        b.mkdir(parents=True, exist_ok=True)
        p = b / (".probe" + str(os.getpid()))
        p.write_text("x")
        p.unlink()
    except PermissionError:
        # sudo strips most env vars; re-export the ones that decide what we remove
        env = [f"{v}={os.environ[v]}" for v in ("DEEPWORK_PREFIX", "DEEPWORK_DIR") if v in os.environ]
        os.execvp("sudo", ["sudo", *env, sys.executable, os.path.abspath(__file__)])


def edit_path(d):
    # drop d from the user PATH (Windows)
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                       winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)
    try:
        val, typ = winreg.QueryValueEx(k, "Path")
    except FileNotFoundError:
        winreg.CloseKey(k)
        return
    parts = [p for p in (val or "").split(";") if p and p.lower() != d.lower()]
    winreg.SetValueEx(k, "Path", 0, typ, ";".join(parts))
    winreg.CloseKey(k)
    # broadcast so Explorer and new shells pick the PATH change up
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 2, 5000, None)


def main():
    elevate()
    dst = Path(prefix()) / ("deepwork" if WIN else os.path.join("lib", "deepwork"))
    installed = dst / "deepwork.py"
    # 1. Turn focus mode off first: never delete the filter while the system
    #    resolver still points at it. `off` is defensive — it sweeps the links
    #    and works even when the state file holds a dead pid — so running it
    #    whenever a filter is installed is safe and never leaves DNS behind.
    if installed.exists():
        r = subprocess.run([sys.executable, str(installed), "off"],
                           capture_output=True, text=True)
        print(r.stdout.strip() or "turned deepwork off")
    # 2. Drop the command: the shim on Linux, the PATH entry and the autostart
    #    Run key on Windows.
    if WIN:
        edit_path(str(dst))
        deepwork._autostart(False)
        print("removed the PATH entry and the autostart Run key")
    else:
        shim = Path(prefix()) / "bin" / "deepwork"
        if shim.exists():
            shim.unlink()
            print(f"removed the command shim {shim}")
    # 3. Remove the installed files, then tidy up the now-empty directories the
    #    installer created. rmdir only succeeds on an empty directory, so a
    #    shared prefix that holds other tools is never disturbed.
    if dst.exists():
        shutil.rmtree(dst)
        print(f"removed the installed files at {dst}")
    for d in (Path(prefix()) / "bin", Path(prefix()) / "lib", Path(prefix())):
        try:
            d.rmdir()
        except OSError:
            pass
    # 4. Remove the config directory. Guard: only ever delete a directory that
    #    is actually a deepwork config dir — its name says so, or it holds the
    #    files deepwork writes — never something the env var just points at.
    if os.path.isdir(deepwork.DIR):
        names = set(os.listdir(deepwork.DIR))
        if (os.path.basename(os.path.normpath(deepwork.DIR)) == "deepwork"
                or names & {"config.json", "state.json", "blocked.log", "daemon.log"}):
            shutil.rmtree(deepwork.DIR)
            print(f"removed the config directory {deepwork.DIR}")
        else:
            print(f"config directory {deepwork.DIR} does not look like a deepwork dir; leaving it")
    print("deepwork is uninstalled")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.exit("deepwork uninstaller: " + str(e))
