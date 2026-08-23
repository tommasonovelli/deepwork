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
the Windows autostart key, and leaves your config directory in place. `python3
uninstaller.py` is the complete removal — the one to run when you want the config gone
too. It turns deepwork off first whether or not it was installed through the installer
(if the installed copy is missing it runs the `deepwork.py` sitting next to it), then
removes the installed files and the `deepwork` command (on Windows the PATH entry and
the autostart Run key), and finally the config directory. Deleting the config directory
is the only step that asks: it prompts on a terminal, `--yes` skips the prompt, and
with no tty to confirm on it refuses rather than assume. Only a directory that actually
holds deepwork's files is deleted — being *named* `deepwork` is not evidence. If
turning the filter off fails, the uninstaller stops and deletes nothing: the config
directory holds `state.json`, the only record of how to get DNS back. Nothing else
under the install prefix is touched — only what the installer created is removed. The
installer's uninstall is a safe no-op when nothing is installed; the uninstaller is
not, because it still has to decide what to do with the config directory.
`deepwork on` and `deepwork off` re-run themselves with root (Linux, via sudo) or
administrator (Windows, via UAC) privileges. That is not an accident: turning focus mode
on means repointing the system resolver, and only a privileged process may change that.
Everything else — add, remove, list, status — runs unprivileged.

## Use

    deepwork                this help (every command explained)
    deepwork on             start focus mode
    deepwork off            stop focus mode
    deepwork add <url>      allow sites (github.com, https://x.example/path, ...)
    deepwork remove <url>   take sites off the list
    deepwork list           show the whitelist; lifeline domains are marked (locked)
    deepwork status         "on", "off", or "off" with a warning, plus the number of sites

`add` and `remove` accept several sites in one command and print one line per site,
each naming its subject. `--help`, `-h` and `help` print this help and exit 0; an
unknown command is reported by name and exits 2; a known command with a missing
argument says what is missing. `status` can also answer "off" with a warning — the
filter is dead but the resolver still points at it. That half-state is described
under "The data directory".

## How it works

**The resolver switch.** The machine normally resolves through systemd-resolved (Linux)
or whatever DNS servers Windows has on its interfaces. `on()` first captures what the
machine is using right now (`upstream()`: the `nameserver` lines of
`/run/systemd/resolve/resolv.conf` on Linux, the servers of the active interface indexes
on Windows — loopback addresses are skipped, so the filter never ends up forwarding to
itself), then starts the filter, then moves the resolver to 127.0.0.1:53
(`dns_switch()`: `resolvectl dns <link> 127.0.0.1` plus `resolvectl domain <link> "~."`
on Linux, `Set-DnsClientServerAddress` per interface on Windows). If the capture comes up
empty — the link's DNS was wiped, or already points here — the filter starts with the
`config.json` upstream list instead. `off()` puts the saved links back with
`dns_restore()`; on Linux that is not a plain `resolvectl revert` but the verified
multi-step restore described under "The ordering of `on()`".

**The filter.** `serve()` binds UDP and TCP on 127.0.0.1:53 (and on ::1, best effort)
and drives both sockets with `select`. The port is `DEEPWORK_PORT` when set and valid;
an out-of-range or non-numeric value falls back to 53 with a note on stderr. The select
loop never resolves anything itself: it
reads a query and hands it to a thread pool, because forwarding waits up to 2s for an
upstream and doing that inline put every other query — blocked ones included — in a
queue behind it. UDP work goes to a pool of 64 workers, TCP to a separate pool of 8 — a
stalled TCP client pins its worker for the whole read timeout, and enough of those would
starve UDP, the path that actually matters; TCP is only the rare fallback. A worker
parses the hostname straight off the wire (`qname()`: the DNS labels starting at byte
12). It is bounds-checked, so it never reads past the end of the packet, and a
compression pointer is treated as malformed — a pointer has no meaning in a question the
filter is about to forward. `refresh()` runs in the loop, where it is still
single-threaded, and each worker gets the config snapshot it produced, so there is no
lock anywhere. Allowed queries are sent byte-for-byte unchanged to the first upstream
that answers (`forward()`; each captured upstream tried in order, with the `config.json`
upstream list as fallback) and the reply is relayed verbatim. `forward()` opens a
connected UDP socket, so the kernel drops datagrams from any source but the upstream,
and it discards any reply whose transaction id does not match the query's; one deadline
bounds the whole exchange, so a flood of non-matching replies cannot hold a worker open
past the 2s. A query no upstream answers gets a SERVFAIL. TCP clients may pipeline
several queries on one connection (RFC 7766) and get one answer for each. Blocked
queries get an NXDOMAIN that `synth()` builds by hand from the question — it echoes the
query id, sets the NXDOMAIN flag byte, and appends the question section, always
reporting exactly one question and capping the echo so the reply cannot grow past 512
bytes. A query that cannot be parsed is answered with a FORMERR rather than dropped; the
one exception is a datagram too short to hold a 12-byte DNS header, which carries no
transaction id that any reply could echo, so it is discarded.

**The policy.** `allowed(name, sites)` is the whole thing. A name passes when it has no
dot at all, when it ends in a local suffix (`.lan`, `.local`, `.home.arpa`,
`.internal`, `.in-addr.arpa`, `.ip6.arpa`), or when it equals — or is a subdomain of —
anything in the whitelist plus the ALWAYS lifeline. So allowing `github.com` also allows
`api.github.com`, while `raw.githubusercontent.com` needs its own entry. Every entry
goes through `norm()` — lowercase, strip scheme, query, fragment, path, port and a
leading `*.` or `www.` — in one place, `_clean()`, which both `load()` and the filter's
`refresh()` call, so the CLI and the running filter can never read the same file two
different ways. `_clean()` also de-duplicates, so four entries that all reduce to
`a.com` become one; entries that cannot be a hostname are dropped on read.

**Live config.** The filter stats `config.json` on every query and reloads it when the
mtime changes (`refresh()`), so `deepwork add` — or your editor — takes effect on the
very next query of a filter that is already running. A file that cannot be parsed is not
half-applied: the last good config stays in place and the filter keeps working until the
file is fixed.

**The ordering of `on()` is deliberate.** Capture the upstream first, start the filter,
prove it answers by sending it a probe query for an ALWAYS domain (`probe()` polled by
`wait_up()`), and only then move the resolver. `state.json` is written *before* the
resolver is moved, so even a kill between the two leaves `off` the record it needs. As
a last safety gate, after the switch `on()` resolves one ALWAYS domain through the
*system* resolver; if that raises, it calls `off()` — revert DNS, kill the filter, drop
state — and reports the failure. A machine is never left without working DNS by `on`.
`on()` also holds an exclusive lock (`state.lock`) for the whole run, so two concurrent
invocations cannot both proceed — the second would overwrite the first's `state.json` —
and the loser reports "already on".
`off()` is just as defensive: it reads the recorded links straight from `state.json`
even when the filter's pid is dead, sweeps the current default routes and every
interface for any link whose DNS still points at the deepwork loopback resolver, and
restores those. It signals the recorded pid only after verifying it is actually this
filter (`is_daemon()`: on Linux, the command line in `/proc/<pid>/cmdline`) — a
`state.json` can outlive a reboot and its pid be reassigned to something else entirely,
and `off` runs as root. It then waits for the filter to exit before returning,
escalating to SIGKILL, so the port is free and `deepwork off && deepwork on` works.
Restoring is not just `resolvectl revert`: revert drops the link's whole runtime
configuration, including the servers NetworkManager pushed over D-Bus, and NM does not
push them again until the device is reactivated — a plain revert left the machine with
no resolver at all until the next reboot. So `off()` reverts, then — if the link is not
healthy — asks NetworkManager to reapply, then falls back to writing down what `on()`
saved for that link. Healthy means more than "has a DNS server": `_needs_repair()`
fires when the link still points at the loopback filter *or* has no DNS at all — a
failed `revert` leaves 127.0.0.1 in place, and a link that would resolve through a
filter that is about to be gone is as broken as one that resolves through nothing. Every
helper call goes through `_run()`, which treats a missing binary (no `nmcli` on a
systemd-networkd machine) as a failed call rather than an abort, so a missing helper
never stops the restore partway through. If a link that carries a default route still
ends up without DNS, `off` says so and names the command that fixes it — a broken `off`
is never silent, and never leaves the machine mute.

**The data directory.** Everything lives in `~/.config/deepwork` (Linux) or
`%APPDATA%\deepwork` (Windows) — `DEEPWORK_DIR` overrides the location:

- `config.json` — `{"sites": [...], "upstream": [...]}`, the only file you edit by
  hand, and it is meant to be edited by hand: write whatever form of URL you like,
  `norm()` reduces it on read. Defaults: github.com, stackoverflow.com, python.org,
  wikipedia.org. A missing file is a normal first run; a file that is present but will
  not parse — or whose `sites`/`upstream` are not lists of strings — is refused with an
  error naming the file and the problem, and it is never overwritten, so a broken
  hand-edit surfaces instead of silently coming back as the defaults on the next `add`.
  Loopback addresses in `upstream` are dropped — pointing the filter at itself would
  make it query itself. Writes go through a temporary file renamed over the target,
  keeping the old permissions, so an interrupted write cannot leave a truncated
  `config.json` behind.
- `state.json` — written when focus mode turns on: the filter's pid, the links that
  were repointed, the captured upstream and — on Linux — each of those links' own DNS
  servers and domains, which is what `off` needs to put things back (on Windows the
  interfaces are handed back to their defaults via `ResetServerAddresses` instead).
  Deleted on `off`. If the filter dies while focus mode is on, the file is kept: `off`
  still uses the record to undo the resolver switch, and `status` reports off *with a
  warning* — the resolver still points at a filter that is not running — naming the
  command that fixes it. That is the one state where the machine resolves nothing, so
  it must not read as ordinary.
- `blocked.log` — one blocked hostname per line, most recent last, wiped when it grows
  past 32 KB. The cap is enforced while the filter runs, not only at startup, and the
  set of already-logged hostnames is bounded too, so a long session against an ad-heavy
  browser cannot grow it without limit. Useful for spotting which domains a half-loaded
  page still needed.
- `daemon.log` — the filter's stdout/stderr. If the filter dies at startup, `on`
  prints the last line of this file as the reason.

## Map of the file

| Section | Functions | What it does |
| --- | --- | --- |
| Paths & constants | `_cfgdir`, `ALWAYS`, `LOCAL`, `DEFAULTS` | where data lives, the lifeline, local suffixes |
| Config | `load`, `save`, `_clean`, `norm`, `ConfigError` | read/write `config.json`, normalise and validate user input |
| Policy | `allowed` | the whole allow/block decision |
| Filter | `serve`, `qname`, `refresh`, `synth`, `forward`, `resolve`, `answer_udp`, `answer_tcp` | DNS server on 127.0.0.1:53, UDP + TCP; 64 UDP workers, a separate pool of 8 for TCP |
| Resolver | `upstream`, `_links`, `_all_links`, `_link_config`, `_has_dns`, `_loopback_dns`, `_needs_repair`, `dns_switch`, `dns_restore` | capture, repoint and restore the system DNS |
| State | `alive`, `is_daemon`, `state`, `probe`, `_autostart`, `_start_daemon`, `wait_up` | pid liveness and identity, startup probe, Windows autostart |
| Commands | `on`, `off`, `status`, `add_site`, `remove_site` | the user-facing commands |
| Dispatch | `elevate`, `main`, `USAGE` | privilege re-exec, argument routing, help |

## The lifeline

`ALWAYS` — `anthropic.com`, `claude.ai`, `claude.com`, `claudeusercontent.com`,
`deepseek.com`, `pi.dev`, `connectivity-check.ubuntu.com` — is hardcoded and always
allowed. These are not in `config.json`; `add` refuses them and `list` marks them
`(locked)`. The reason for the first six: this machine drives Claude Code and pi, and
OAuth tokens are refreshed on `platform.claude.com` (a subdomain of `claude.com`), so
blocking those domains would drop the session at the next token renewal and cut the
tools that maintain the tool.

`connectivity-check.ubuntu.com` is there for a different reason. It is the URI
NetworkManager fetches to decide whether the machine is online (`NetworkManager
--print-config`, `[connectivity] uri`). With it blocked, `nmcli networking
connectivity` reports `limited`, the desktop puts a warning on the network icon, and
applications that check for a captive portal start behaving as if one were in the way —
which looks exactly like the connection breaking, even though every whitelisted site
still resolves.

## Honest limits

- A whitelisted site can still look half-broken until you also allow the CDN domains it
  pulls from (fonts, images, API subdomains). When a page half-loads, check
  `blocked.log` for the hostnames it needed and add them with `deepwork add`.
- DNS filtering is not a firewall. A program that connects to a raw IP address, or that
  ships its own DNS-over-HTTPS resolver, is not stopped.
- On Windows the setting survives a reboot by design: turning on adds a Run key that
  restarts the filter at login, so a rebooted machine is still in focus mode.
  `deepwork off` is always the way out. On Linux a reboot clears everything, because
  systemd-resolved settings are runtime-only.
- `deepwork off` only touches links whose DNS is still pointed at the deepwork
  loopback resolver (127.0.0.1/::1): a DNS server you had set by hand on another
  interface is never clobbered, and a process is only signalled once `off` has verified
  it is actually the filter — a pid from a `state.json` that survived a reboot can
  belong to something else. If a link that carries a default route cannot be given its
  DNS back, `off` says so instead of silently pretending everything is fine.
