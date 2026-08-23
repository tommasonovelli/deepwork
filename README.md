# DeepWork

A focus tool. While deepwork is on, only whitelisted sites and a few hardcoded lifeline
domains resolve; everything else gets an NXDOMAIN answer and the page never loads. The
mechanism is a tiny local DNS filter that deepwork runs on 127.0.0.1:53, with the
machine's real resolver pointed at it for as long as focus mode lasts.

## Install

Clone the repo, then:

    python3 installer.py        # Linux
    py installer.py             # Windows

The installer copies `deepwork.py` to a system location, adds a `deepwork` command to
your PATH, and prints the one next step: open a new terminal and run `deepwork`.
Updating is the same command again: `git pull`, then run the installer once more — it
deletes the previous installation first and copies fresh, so stale files never survive,
and your config is never touched. Uninstall is `python3 installer.py uninstall`: it
turns deepwork off first if it is on, removes the installed files, the PATH entry and
the Windows autostart key, and leaves your config directory in place.
`deepwork on` and `deepwork off` re-run themselves with root (Linux, via sudo) or
administrator (Windows, via UAC) privileges. That is not an accident: turning focus mode
on means repointing the system resolver, and only a privileged process may change that.
Everything else — the menu, add, remove, list, status — runs unprivileged.

## Use

    deepwork                the interactive menu (turn on/off, add, remove)
    deepwork on             start focus mode
    deepwork off            stop focus mode
    deepwork add <url>      allow a site (github.com, https://x.example/path, ...)
    deepwork remove <url>   take a site off the list
    deepwork list           show the whitelist; lifeline domains are marked (locked)
    deepwork status         "on" or "off" plus the number of sites

## How it works

**The resolver switch.** The machine normally resolves through systemd-resolved (Linux)
or whatever DNS servers Windows has on its interfaces. `on()` first captures what the
machine is using right now (`upstream()`: the `nameserver` lines of
`/run/systemd/resolve/resolv.conf` on Linux, the servers of the active interface indexes
on Windows), then starts the filter, then moves the resolver to 127.0.0.1:53
(`dns_switch()`: `resolvectl dns <link> 127.0.0.1` plus `resolvectl domain <link> "~."`
on Linux, `Set-DnsClientServerAddress` per interface on Windows). `off()` puts the saved
links back with `dns_restore()` (`resolvectl revert` / `ResetServerAddresses`).

**The filter.** `serve()` binds UDP and TCP on 127.0.0.1:53 (and on ::1, best effort)
and drives both sockets with `select`. For each query it parses the hostname straight
off the wire (`qname()`: the DNS labels starting at byte 12), applies the policy, and
either forwards or blocks. Allowed queries are sent byte-for-byte unchanged to the first
upstream that answers (`forward()`; 2s timeout, each captured upstream tried in order,
with the `config.json` upstream list as fallback) and the reply is relayed verbatim.
Blocked queries get an NXDOMAIN that `synth()` builds by hand from the question — it
echoes the query id, sets the NXDOMAIN flag byte, and appends the question section
verbatim.

**The policy.** `allowed(name, sites)` is the whole thing. A name passes when it has no
dot at all, when it ends in a local suffix (`.lan`, `.local`, `.home.arpa`,
`.internal`, `.in-addr.arpa`, `.ip6.arpa`), or when it equals — or is a subdomain of —
anything in the whitelist plus the ALWAYS lifeline. So allowing `github.com` also allows
`api.github.com`, while `raw.githubusercontent.com` needs its own entry. `add` and
`remove` normalise their argument (`norm()`: lowercase, strip scheme, path, port and a
leading `www.`) before touching the list.

**Live config.** The filter stats `config.json` on every query and reloads it when the
mtime changes (`refresh()`), so `deepwork add` takes effect on the very next query of a
filter that is already running.

**The ordering of `on()` is deliberate.** Capture the upstream first, start the filter,
prove it answers by sending it a probe query for an ALWAYS domain (`probe()` polled by
`wait_up()`), and only then move the resolver. As a last safety gate, after the switch
`on()` resolves one ALWAYS domain through the *system* resolver; if that raises, it
calls `off()` — revert DNS, kill the filter, drop state — and reports the failure. A
machine is never left without working DNS by `on`. Conversely `off()` rescues a broken
setup even when state is missing: it reverts the current default links if it has no
saved ones.

**The data directory.** Everything lives in `~/.config/deepwork` (Linux) or
`%APPDATA%\deepwork` (Windows):

- `config.json` — `{"sites": [...], "upstream": [...]}`, the only file you edit by
  hand. Defaults: github.com, stackoverflow.com, python.org, wikipedia.org.
- `state.json` — written when focus mode turns on: the filter's pid, the links that
  were repointed, and the captured upstream. Deleted on `off`, and deleted
  automatically when `status` finds the pid dead.
- `blocked.log` — one blocked hostname per line, most recent last, truncated at 32 KB.
  The add screen reads it to offer recent blocked domains as suggestions.
- `daemon.log` — the filter's stdout/stderr. If the filter dies at startup, `on`
  prints the last line of this file as the reason.

## Map of the file

| Section | Functions | What it does |
| --- | --- | --- |
| Paths & constants | `_cfgdir`, `ALWAYS`, `LOCAL`, `DEFAULTS` | where data lives, the lifeline, local suffixes |
| Config | `load`, `save`, `norm` | read/write `config.json`, normalise user input |
| Policy | `allowed` | the whole allow/block decision |
| Filter | `serve`, `qname`, `refresh`, `synth`, `forward`, `resolve` | DNS server on 127.0.0.1:53, UDP + TCP |
| Resolver | `upstream`, `_links`, `dns_switch`, `dns_restore` | capture and repoint the system DNS |
| State | `alive`, `state`, `probe`, `_autostart`, `_start_daemon`, `wait_up` | pid liveness, startup probe, Windows autostart |
| Commands | `on`, `off`, `status` | the elevated entry points |
| TUI | `chrome`, `box`, `frame`, `key`, `home`, `add_screen`, `remove_screen` | the ANSI menu |
| Dispatch | `elevate`, `main` | privilege re-exec, argument routing |

## The lifeline

`ALWAYS` — `anthropic.com`, `claude.ai`, `claude.com`, `claudeusercontent.com`,
`deepseek.com`, `pi.dev` — is hardcoded and always allowed. These are not in
`config.json`; `add` refuses them, the remove screen never lists them, and `list` marks
them `(locked)`. The reason: this machine drives Claude Code and pi, and OAuth tokens
are refreshed on `platform.claude.com` (a subdomain of `claude.com`), so blocking those
domains would drop the session at the next token renewal and cut the tools that maintain
the tool.

## Honest limits

- A whitelisted site can still look half-broken until you also allow the CDN domains it
  pulls from (fonts, images, API subdomains). That is exactly what the numbered
  suggestions on the add screen are for: when a page half-loads, `blocked.log` already
  has the hostnames it needed, and pressing 1–8 adds them.
- DNS filtering is not a firewall. A program that connects to a raw IP address, or that
  ships its own DNS-over-HTTPS resolver, is not stopped.
- On Windows the setting survives a reboot by design: turning on adds a Run key that
  restarts the filter at login, so a rebooted machine is still in focus mode.
  `deepwork off` is always the way out. On Linux a reboot clears everything, because
  systemd-resolved settings are runtime-only.
- `deepwork off` reverts the default links even when deepwork was never on. That is the
  rescue path, and it also clears a DNS server you had set by hand on that link.
