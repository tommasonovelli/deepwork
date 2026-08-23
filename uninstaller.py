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
    # probe the nearest existing parent: creating a probe file here would create
    # the very directory the probe is meant to test
    probe = b
    while not probe.exists():
        probe = probe.parent
    if not os.access(probe, os.W_OK):
        # sudo strips most env vars; re-export the ones that decide what we remove
        env = [f"{v}={os.environ[v]}" for v in ("DEEPWORK_PREFIX", "DEEPWORK_DIR") if v in os.environ]
        os.execvp("sudo", ["sudo", *env, sys.executable, os.path.abspath(__file__), *sys.argv[1:]])


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


def main(yes=False):
    elevate()
    dst = Path(prefix()) / ("deepwork" if WIN else os.path.join("lib", "deepwork"))
    installed = dst / "deepwork.py"
    # 1. Turn focus mode off first: never delete the filter while the system
    #    resolver still points at it. `off` is defensive — it sweeps the links
    #    and works even when the state file holds a dead pid — so running it
    #    is safe and never leaves DNS behind. When deepwork was never installed
    #    through installer.py, the sibling copy next to this uninstaller still
    #    knows how to turn it off.
    script = installed if installed.exists() else Path(deepwork.__file__)
    r = subprocess.run([sys.executable, str(script), "off"], capture_output=True, text=True)
    if r.returncode:
        # deleting the config directory now would destroy state.json, the only
        # record of what to restore: abort while the user can still recover
        sys.exit("deepwork uninstaller: off failed: " + (r.stderr.strip() or r.stdout.strip()
                or "no error output") + "\nrun: sudo deepwork off first")
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
    # 3. Remove the installed files.
    if dst.exists():
        shutil.rmtree(dst)
        print(f"removed the installed files at {dst}")
    # 4. Remove the config directory. Guard: only ever delete a directory that
    #    holds the files deepwork writes — its name alone is not evidence — and
    #    only with confirmation (or --yes). Without a tty to confirm on, refuse
    #    rather than assume.
    if os.path.isdir(deepwork.DIR):
        names = set(os.listdir(deepwork.DIR))
        if not names & {"config.json", "state.json", "blocked.log", "daemon.log"}:
            print(f"config directory {deepwork.DIR} does not look like a deepwork dir; leaving it")
        elif yes:
            shutil.rmtree(deepwork.DIR)
            print(f"removed the config directory {deepwork.DIR}")
        elif sys.stdin.isatty():
            print(f"about to delete the config directory {deepwork.DIR}")
            if input("type yes to continue: ").strip().lower() == "yes":
                shutil.rmtree(deepwork.DIR)
                print(f"removed the config directory {deepwork.DIR}")
            else:
                print("config directory kept")
        else:
            sys.exit("deepwork uninstaller: refusing to delete the config directory "
                     "without confirmation; re-run with --yes")
    print("deepwork is uninstalled")


if __name__ == "__main__":
    try:
        if sys.argv[1:] not in ([], ["--yes"]):
            print("usage: python3 uninstaller.py [--yes]")
            sys.exit(1)
        main("--yes" in sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.exit("deepwork uninstaller: " + str(e))
