# TNT — TEC Network Tool

<!-- download: rewritten by tools/set_release_links.py -->

## [⬇ Download TNT for Windows](https://github.com/rhuntertec/TNT/releases/latest)

**Latest release: 1.21.2** — [TNT-Setup-1.21.2.exe](https://github.com/rhuntertec/TNT/releases/download/v1.21.2/TNT-Setup-1.21.2.exe) · [release notes](https://github.com/rhuntertec/TNT/releases/latest) · [checksum](https://github.com/rhuntertec/TNT/releases/download/v1.21.2/TNT-Setup-1.21.2.exe.sha256)

Windows 10 or 11, 64-bit. The build is not code-signed, so SmartScreen will warn: choose
**More info**, then **Run anyway**. Once installed, TNT updates itself from this page.

<!-- /download -->

TNT is an installable Windows 10/11 network discovery, diagnostic and monitoring tool
built for Total Electronics field and office use. A Windows service does the measuring
from the moment the PC boots (no login needed); a small tray app opens a local dashboard
in a WebView2 window. Everything runs on the machine, talks only to `127.0.0.1`, and keeps
working while the internet is down (no CDN, no cloud).

## The twelve functions

| Tile | What it does |
|---|---|
| **Network info** | Every adapter (internet-facing first) with IPv4/IPv6 addresses, masks, gateways, DNS, MAC, link speed, DHCP; grouped by subnet, every value copyable. A **realtime throughput** card graphs what each adapter is really moving, once a second, over 10 s to 30 min — receive and send filled on one auto-scaling axis, each with its window average drawn across it, the current rate in Kbps/Mbps/Gbps and the packet and byte totals Windows shows in the adapter status dialog. Every NIC that is carrying traffic gets its own graph, a VPN tunnel included — and a checkbox at the foot of each adapter card below keeps one you never want to see off it. An adapter that got no DHCP answer (169.254.x.x), has a duplicate address, a gateway outside its subnet or no DNS servers says so on its card. When the PC joins another network (another cable, Wi-Fi, a static address) every page follows within seconds, with one "Network changed" toast. |
| **Ping** | Continuous 1-per-second ICMP monitoring of the gateway (the special host `gateway` always follows the current default route), `1.1.1.1`, `totalelectronics.com` and any host you add; traffic lights, 5-minute sparklines, 1-min/24-h loss and latency, loaded (1200 B) / unloaded (32 B) payloads. |
| **Outages** | State machine over the ping samples (3 misses = outage, 3 replies = recovered) with per-target and *total* (local / internet) outages, a 24-hour timeline and a year of history. |
| **Speed** | Scheduled internet speed tests (default every 15 min) with download, upload, latency and jitter, history charts and pattern analysis ("slower between 19:00 and 22:00"). |
| **Discovery** | On-demand LAN scan: ping sweep, TCP port probe (22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443 by default), ARP/MAC + vendor, reverse DNS / NetBIOS names, automatic device type (Router / DW Server / Camera / Phone / Wifi); sortable results, one-click "add as ping target", open ports are clickable links. The scanner is built in; nothing else to install. |
| **WiFi** | A Wi-Fi survey: every access point (BSSID) this PC can see or has seen since TNT was opened, on 2.4, 5 and 6 GHz. A network list, a sortable radio table (channel and width, signal, PHY / Wi-Fi generation, security, vendor), signal strength over time (5 min / 15 min / 1 h / the whole session) and a spectrum chart per band where each access point is a shape as tall as its signal and as wide as its channel; click a network to highlight all of its access points everywhere. It runs inside the TNT window (Windows only shows nearby access points to a signed-in user who allows location access, which the service is not), scans actively only while the page is on screen, and needs no admin rights. |
| **Tools** | Field tools. First one: a **DHCP server** you switch on to give addresses to gear that has none. It checks every NIC for an existing DHCP server first (big red warning if one answers), serves 5 addresses next to the PC's own IP (or moves a DHCP-assigned Ethernet port to `172.16.4.100/24` and serves `.101–.105`), lists every client like a Discovery result (IP, MAC, vendor, open ports) and puts the NIC back exactly as it was when switched off. See [DHCP server](#dhcp-server-tools). Above the cards a **Quick Tools** row of one-click tools that need no settings (IP Release/Renew, Flush DNS); below the DHCP server: LAN throughput, a port-forward check, Traceroute, a TFTP server, a subnet calculator, DNS lookups and the saved Wi-Fi networks with their passwords; the tile names them under the DHCP server's state. |
| **Reports** | Site reports for the customer networks TNT is used on. **Full Scan** (the button on the Reports page) runs a speed test, a Discovery scan and a Wi-Fi scan, adds the pings and outages this PC recorded on that site's network in the last 7 days (every visit, nothing from other networks; the network is known by its router) and saves it all as a report for the site you name; earlier site names are suggested as you type, and a network scanned before starts with its site's name, so repeat visits file together (a phone hotspot or travel router you carry between sites can be marked as your own, and is suggested nothing). The Reports page shows a report in a compact layout (key numbers, network, speed, ping, outages, devices, Wi-Fi), browses the saved reports by site, exports a report as a PDF and compares any two, section by section, so a customer's network can be shown next to a known good one. Reports stay on this PC until deleted. |
| **Packet capture** | A stripped-down network analyser on its own page. Pick an adapter that is up, hit Start, and the packets arrive in the list as they are caught — the number, the time of day, the time since the capture began, the addresses, the protocol, the length and a one-line summary — with filters for an IP address, a MAC address and the protocols (ICMP, ARP, DNS, DHCP, HTTP, HTTPS, TCP, UDP, RTSP, RTP, SIP). Click a packet for its protocol tree and hex dump. A capture that holds a SIP call says so, lists the calls and rebuilds a G.711 call's audio so you can play it in the page. Stop keeps what was caught; Save writes it as a pcapng file Wireshark opens, Open reads a capture back into the list — one TNT saved, or any capture file on this PC by its path (one from Wireshark, a switch or a colleague) — and Discard throws it away. It records one adapter through a capture session Windows itself provides — nothing is installed, no Npcap, no Wireshark, no third-party driver — and it needs a Windows administrator account. See [Packet capture](#packet-capture). |
| **Pro AV** | Point it at a broadcast-audio network — Dante, AES67, Ravenna, SMPTE ST 2110, Q-LAN — and it tells you what is on it, what is streaming, what clock everything is following and what is wrong. It only listens: it joins the mDNS, SAP and PTP groups and reads what is already being announced to every device on the VLAN, so it is safe to run during a show. You get the devices (name, model, firmware, maker, what each one offers), the announced streams with the bandwidth each really costs on the wire, the whole PTP clock tree — grandmaster, what it is locked to, the boundary and transparent clocks in the way, everyone following it — and a findings list, worst first, that says what it measured and what to do about it. Two clock trees running at once, a free-running grandmaster, a stream announced against a clock that is no longer there, sync arriving unevenly, no IGMP querier on the VLAN. It draws the two diagrams a single port can honestly produce: the clock tree, and the stream flow map. See [Pro AV](#pro-av). |
| **SIP** | Would calls work on this network, and if they do not, why not. It starts by **qualifying the line** out of what TNT has already been collecting — the ping history for this network and the last speed test — and grades it in two halves, because they send you to different places: the **LAN leg** to the gateway (bad here is the switch, the cabling or Wi-Fi, and it is in the building) and the **internet leg** (bad here with a clean gateway is the circuit or the provider, and these are the numbers to tell them). Name your PBX, SBC or registrar and it is graded as a third leg, on the path the calls actually take. Above the legs it puts the three numbers a call is judged by — a MOS, the average delay and the average jitter — taken from whichever leg is weakest, because that is the one that limits the call. Then three tools: a **SIP ALG check** that sends an OPTIONS to your own phone system from two source ports and compares what comes back with what went out — a SIP server has to echo Via, Call-ID, CSeq and From exactly as it received them, so anything different was changed in transit; a **STUN test** that asks two servers from one socket, because two different external ports is the NAT that causes one-way audio, with an optional binding-lifetime test for the NAT that forgets a mapping between registrations; and **call flows** — browse to a capture on this PC (or two, one from each side of the network) and every SIP call is drawn as a ladder: INVITE, ringing, answer, the RTP, the BYE. Click any row for that packet's full headers, and play the audio of a call or of one direction on its own. Two captures are matched on Call-ID and the clock difference between them is measured, not assumed — and a header that differs between the two sides is the one conclusive proof that something in the middle is rewriting your SIP. See [SIP](#sip). |

| **Faults** | What is wrong with this network, found without asking it anything. It starts with the service and watches three things no other tool looks at: every adapter’s error and discard counters, their live address configuration, and the ARP table over time. Frames arriving damaged is cabling, a connector or a duplex mismatch; frames dropped for want of a buffer is congestion — they are never added together, because they send you to opposite ends of the problem. One address answered by two MAC addresses is the duplicate IP that makes a device work intermittently for no visible reason. Everything is counted from when TNT started watching, not from the adapter’s lifetime total, and it says how long that has been. Nothing is sent and no administrator rights are needed. |

Any of **Speed, Discovery, WiFi, Packet capture, Pro AV and SIP** can be switched off in
Settings for a site that never uses them. A tool that is off has no tile and no page, and its
background work stops with it — no scheduled speed tests, no section for it in a Full Scan.

Plus: PDF export, a diagnostics page, light and dark theme.

## Architecture in one paragraph

`TNTService.exe` is a Windows service (`TNTService`, LocalSystem, automatic start) that runs
the monitoring engine and a stdlib HTTP server on **127.0.0.1:7130** serving the UI, a JSON
API and a Server-Sent-Events stream. `TNT.exe` is the tray icon (pystray) + window (pywebview
on WebView2) that simply shows `http://127.0.0.1:7130`. The dashboard also works in any
browser on the same machine. See `docs/ARCHITECTURE.md` for the module contracts and
`docs/DESIGN.md` for the visual language.

## System requirements

* **64-bit (x64) Windows 10 version 1809 (build 17763) or newer, or Windows 11.** That
  includes Windows 10 Enterprise LTSC 2019 and LTSC 2021. Not supported: 32-bit Windows,
  Windows 10 on ARM, Windows 7/8.1, older Windows 10 releases, Windows Server Core.
  Untested: Windows 11 on ARM (x64 emulation) and Windows Server 2019/2022/2025 with Desktop
  Experience.
* **.NET Framework 4.7.2 or later** for the TNT window. It is built into Windows 10 1803+ and
  Windows 11, so there is nothing to download. No .NET 6/7/8 runtime and no Visual C++
  Redistributable are needed.
* **Microsoft Edge WebView2 Runtime 111 or later** for the window. Setup installs or updates
  it when the PC is online; offline PCs need Microsoft's Evergreen Standalone Installer.
* **Administrator rights** to install. The monitoring service itself needs neither .NET nor
  WebView2, and the dashboard also opens in a browser at `http://127.0.0.1:7130`.

Setup checks the Windows version, architecture and .NET Framework first and stops with an
explanation (exit code 1 when silent). A WebView2 problem only produces a warning. The full
matrix with reasons, firewall rules and ports, hardware, antivirus/SmartScreen notes and the
web features behind "WebView2 111" is in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Install

1. Run `TNT-Setup-<version>.exe` (needs admin, x64, Windows 10 1809 or newer; see
   [System requirements](#system-requirements)).
2. Setup stops any previous version, installs to `C:\Program Files\TNT`, registers and
   starts the `TNTService` service, installs or updates the Microsoft Edge WebView2 runtime if
   it is missing or older than 111 (downloaded from Microsoft), adds `TNT.exe --minimized` to
   the HKLM *Run* key and launches the tray icon.
3. Double-click the dynamite icon in the tray (or *Start → TNT*) to open the dashboard.

The tray icon's status dot mirrors the overall traffic light (green / yellow / red, grey when
paused or unreachable) and its menu offers *Open TNT*, *Run speed test now*, *Pause/Resume
monitoring*, *Diagnostics* and *Quit TNT*. Closing the window only hides it; *Quit* closes the
tray client but **monitoring keeps running** in the service. Starting `TNT.exe` again just
brings the existing window to the front.

Uninstall from *Apps & features*. The monitoring data in `%ProgramData%\TNT` is kept unless
you answer *Yes* to "Remove monitoring data?" (the downloaded IP location data in
`%ProgramData%\TNT\geoip` is always removed).

## Where things live

| Path | Contents |
|---|---|
| `C:\Program Files\TNT\` | `TNTService.exe` + `_service\`, `TNT.exe` + `_client\`, `LICENSE`, `THIRD-PARTY-NOTICES.txt`, uninstaller |
| `%ProgramData%\TNT\config.json` | settings (editable; unknown keys are kept, values are clamped, settings a release removed are dropped) |
| `%ProgramData%\TNT\tnt.db` | SQLite (WAL) — per-minute ping aggregates, outages, speed tests, discovery runs, events |
| `%ProgramData%\TNT\logs\tnt-service.log` | service log (rotating, 5 × 5 MB) |
| `%ProgramData%\TNT\logs\pings\YYYY-MM-DD.csv(.gz)` | every single ping sample, one file per day |
| `%ProgramData%\TNT\exports\` | PDF reports |
| `%ProgramData%\TNT\geoip\` | DB-IP Lite IP location data (`dbip-*-lite-YYYY-MM.mmdb`, `manifest.json`, `state.json`), downloaded by the service; always removed on uninstall |
| `%ProgramData%\TNT\captures\` | saved packet captures (`TNT-capture-*.pcapng`) and the running capture's working file; SYSTEM + Administrators only, newest 10 / 2 GB / 7 days, always removed on uninstall |
| `%LOCALAPPDATA%\TNT\client.log` | tray/window client log; `webview\` holds the WebView2 profile |

Retention: 365 days (`retention.days`), trimmed daily at 03:15. Override the data folder
with the `TNT_DATA_DIR` environment variable (used by tests and console runs).

## Ports

TNT owns the port block **7130–7139**:

| Port | Use |
|---|---|
| `7130` | the installed service: UI + `/api` + `/api/events` (SSE), loopback only |
| `7135` | engine in console/dev mode (`python -m tnt --console --port 7135`) |
| `7136` | UI development mock API (`python tools/mock_api.py`) |

`PORT` / `TNT_PORT` override the service port; the client takes `--port`.

## Development

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q                                   # unit tests, no network needed
pytest -q --run-network                     # also the tests that hit the internet

# engine in the foreground on the dev port (Ctrl-C stops it)
python -m tnt --console --port 7135
# tray + window client against it
python client\tray.py --port 7135           # add --debug for WebView2 dev tools
# UI work without the engine: realistic fake API + static files
python tools\mock_api.py --port 7136
python client\tray.py --port 7136           # or open http://127.0.0.1:7136 in a browser
```

Service commands during development (elevated prompt): `python -m tnt install | start |
stop | remove`; the installed exe supports the same verbs (`TNTService.exe install`).
Regenerate icons with `python tools\make_icons.py`.

Layout: `tnt/` (service: `icmp`, `netinfo`, `arp`, `oui`, `pinger`, `outages`, `speedtest/`,
`discovery`, `dhcp`, `export_pdf`, `diagnostics`, `api/`, `engine`, `service`), `client/`
(`tray`, `icons`), `ui/` (vanilla HTML/CSS/JS, no build step), `tools/`, `installer/`, `tests/`.

## Build, sign, package

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1            # everything
powershell -ExecutionPolicy Bypass -File installer\build.ps1 -SkipTests -SkipSign
```

The pipeline (details in `installer/README.md`): venv → `pip install` → `pytest` →
`tools/make_icons.py` → PyInstaller onedir builds of `TNTService.exe` and `TNT.exe` →
`installer/sign.ps1` → Inno Setup (`installer/tnt.iss`) → sign the setup exe. Needs
Inno Setup 6.3+ and, for signing, `signtool.exe` from the Windows SDK.

**Code signing.** `sign.ps1` uses `TNT_SIGN_THUMBPRINT` (certificate in the Windows store,
e.g. on a hardware token) or `TNT_SIGN_PFX` + `TNT_SIGN_PFX_PASSWORD`, and timestamps with
DigiCert. Without a certificate the build is produced unsigned with a warning and Windows
SmartScreen will warn users. **A TLS/HTTPS certificate for totalelectronics.com cannot sign
code** — an Authenticode *code-signing* certificate (OV or EV) issued to Total Electronics by
a public CA is required.

## Licence and the public source tree

TNT is released under the MIT licence (`LICENSE`, Copyright (c) 2026 Total Electronics). The
installer copies `LICENSE` and `THIRD-PARTY-NOTICES.txt` into the program folder. The notices
file lists every third-party component the two bundles redistribute (version, SPDX licence,
copyright, upstream; pystray's LGPL terms are met by publishing the source and build scripts)
and then the licence texts, so it has to be updated whenever what gets bundled changes.

The public GitHub repository is produced from a commit of this repository by
`tools/export_public.py` (standard library only; it never pushes):

```powershell
python tools\export_public.py <public-repo-folder> --dry-run              # check, list the changes
python tools\export_public.py <public-repo-folder> --commit "Public release"
```

* The export is always `HEAD`: the tool refuses to run while tracked files have uncommitted
  changes. `--allow-dirty` skips that check for testing the tool and still exports `HEAD`.
* Left out: every `*.md` (this README and `docs/` included), `PORTS.json`, `.claude/`,
  `.publish-denylist.txt`, the tool itself and its test `tests/test_export_public.py`. A marked
  block in the exported `.gitignore` ignores the private names, so they cannot be committed in the
  public repository.
* Every exported file and path is searched for the entries of `.publish-denylist.txt`
  (gitignored; one entry per line, `#` comments), ignoring case, as UTF-8 and UTF-16LE, and also
  URL-encoded, JSON-escaped and, for a MAC address, in its other spellings and as an IPv6 EUI-64
  interface ID. A match stops the export before the destination is touched and prints
  `file:line` and the entry only.
* An existing destination repository must be a clean earlier export: no uncommitted changes (a
  previous run of the same export without `--commit` is fine), no untracked files that are not
  ignored, its `.gitignore` carrying the export block, and no ignored file that the new ignore
  rules would stop ignoring. Otherwise the export refuses before changing anything and lists the
  files; `--force-dest` lets the sync overwrite and delete them. `--dry-run` runs the same checks.
* The destination is then synced: no-longer-exported files are deleted, new and changed files
  are written (through a temporary file, so a link in the destination is replaced, never written
  through; a name that only changed case is renamed). Untracked files that stay ignored are kept
  and `.git` is only changed by git. A folder without `.git` must be empty; it gets
  `git init -b main` and a local `user.name`/`user.email` (rhunter). Exactly the exported files are
  staged (`git add -f`, so no ignore rule can leave one out), then `git status --short`; a commit
  only with `--commit`. Exit codes: 0 done, 1 denylist match, 2 refused or failed (the message
  says whether the destination may be partially synced).
* In the public tree the tests that read `docs/*.md` skip, and `tests/test_packaging.py` checks
  that no Markdown file of TNT's is bundled.

## Speed tests

Backend is chosen by `speedtest.backend` (`auto` by default). Both backends are built in:

* **cloudflare** (default, `speed.cloudflare.com`) — no client to install, no license
  conditions, brief multi-connection download/upload with latency and jitter.
* **fastcom** (Netflix `fast.com` endpoints) — download-oriented; upload may be unavailable.

`auto` uses Cloudflare and switches to fast.com while Cloudflare is refusing tests (see rate
limits below); an explicit choice falls back to the other one the same way.

Support for the external Ookla Speedtest CLI and nmap was removed in 1.7.0; their settings are dropped from `config.json` on upgrade.

Readings: each direction runs for at least 1.5 s (up to 3× the byte budget) and the reported
Mbps excludes the first quarter of the phase (TCP ramp-up), so fast links get a steadier
figure; the whole-phase figure is kept in the result's raw data (`mbps_full`).

Bandwidth: a Cloudflare run moves at least the byte budgets (50 MB down + 20 MB up,
`download_mb` / `upload_mb`) and keeps each direction going for 1.5 s, capped at 3× the
budget. On a 100 Mbps line that is ≈ 70 MB per run (**≈ 6.7 GB per day** on the default
15-minute schedule); on a gigabit line it can reach ≈ 140 MB per run (≈ 13 GB/day, a fraction
of a percent of the link). Raise `speedtest.interval_min` (60 → a quarter of that) or lower
the byte budgets on metered links. Tests are skipped while all internet targets are in
outage and held off for a minute after the machine wakes from sleep.

Rate limits: neither speed.cloudflare.com nor fast.com publishes limits, and Cloudflare was
seen answering HTTP 429 (Retry-After ≈ 1 h) after a day of very heavy testing from one IP. A
run now makes about 61 requests on gigabit (35 on 100 Mbps). When a service refuses, TNT
puts that backend on cooldown for the Retry-After period, immediately retries the slot with
the other free service, records nothing fake if both refuse, and spaces tests out (15 → 30 →
60 min) until one succeeds. Sites with several TNT installs behind one public IP should raise
`speedtest.interval_min`; the long-term fix is a self-hosted endpoint (LibreSpeed/iperf3 at
totalelectronics.com).

## DHCP server (Tools)

The Tools tile's DHCP server is for the bench and the site visit: a camera or NVR fresh out
of the box, a switch stack with nothing handing out addresses, a device you only want to
reach for five minutes. It is **always off after the service starts** and only runs while
the switch in the UI is on.

* **Turning it on** first probes every connected network port for an existing DHCP server
  (it asks both the way a DHCP relay would and the way a fresh device would, so a server is
  found even when the port's current address is on a different subnet than the one that
  server hands out; allow about 8 s). If one answers, or the NIC already knows one, a red warning explains that two
  DHCP servers on one network hand out conflicting addresses and break devices; *Proceed
  anyway* is there for the cases where you know better (an isolated bench network).
* **Addresses.** By default the server uses the Ethernet port's own address as its identity
  and serves the next 5 addresses (`10.0.0.112` → `10.0.0.113–117`). If that port gets its
  address from DHCP, TNT switches it to static **172.16.4.100/24** and serves
  **172.16.4.101–105**; the range and the lease (1 h by default) are editable. Clients get the
  subnet mask and the PC itself as gateway, **no DNS servers**.
* **Clients** appear in real time as they take an address, shown like Discovery results:
  IP, MAC, vendor, ping and open ports (clickable), with the "add as ping target" button.
* **Putting things back.** Switching the server off (or stopping the service) restores the
  port to DHCP. The change is recorded in the database before it is made, so if the PC
  crashes, loses power or the service is reinstalled the next service start puts the port
  back on DHCP by itself; the `netsh` change is also `store=active`, so a reboot alone undoes
  it. The inbound Windows Firewall rule the server adds for itself (*TNT DHCP server (UDP 67
  in)*, UDP 67 and 68, program-scoped to `TNTService.exe`) is removed by the uninstaller.
* Settings live in `config.dhcp` (`adapter`, `pool_start`/`pool_end` or `pool_size`,
  `lease_s`, `static_ip`/`static_prefix`, `ping_check`, `scan_wait_s`); the on/off state is
  deliberately not a setting.

## Packet capture

The Packet capture page records one adapter's traffic live, on the PC itself, with nothing
installed: the service asks Windows' own built-in packet-capture provider for the frames and
consumes them as they arrive. Npcap, WinPcap and Wireshark are not used and no driver is added.
The page only records — TNT sends nothing of its own.

* **Limits.** A capture stops by itself at whichever comes first: the time you picked (1 min to
  1 hour, 15 min by default), the size you picked (64 MB to 1 GB, 256 MB by default) or 5 million
  packets. The live list holds the newest 50 000 rows, and says so when it has rolled past that;
  the file on disk still holds every packet. Frames that arrive faster than they can be written are
  counted as dropped rather than allowed to grow without bound. A capture needs free disk space of
  twice the size limit plus 1 GB.
* **Filters** are applied by the service over the packets it still holds: an IP address, a MAC
  address and any number of protocol buttons, combined with AND (the protocols among themselves
  with OR). Clicking a row opens that packet's protocol tree and hex dump.
* **SIP calls.** A capture that sees SIP signalling reconstructs the calls — who called whom, the
  state, the duration, the RTP streams — and rebuilds a G.711 call's audio as a WAV you can play
  in the page or save.
* **Files.** While it runs a capture writes `TNT-live-<date>-<time>.pcapng` in
  `%ProgramData%\TNT\captures`, a folder only SYSTEM and Administrators can open; **Save to disk**
  renames it to `TNT-capture-<date>-<time>.pcapng` and **Discard** deletes it. TNT keeps the newest
  10 saved captures (at most 2 GB, nothing older than 7 days) and removes the folder on uninstall.
  Leaving the page with a capture you have not saved asks first. A copy you save elsewhere is an
  ordinary file with none of those protections.
* **Opening a capture.** **Open…** reads a capture back into the list: one of the captures TNT
  saved, or any capture file on this PC — one from Wireshark, one pulled off a switch, one a
  colleague sent. Type or paste its full path, or pick it with **Browse…** (the TNT window has a
  file picker; a browser tab has none, so paste the path there). The path has to be a full local
  one — no `\\server\share` — and the file at most 4 GB. TNT only ever *reads* it: the file is
  never moved, written or deleted, Save does nothing for it, Discard leaves it where it is, and it
  does not join TNT's own saved captures. The list shows the file's first 50 000 packets and says
  so when it holds more.
* **Windows administrator only** — see the security model below.
* **Original code.** The pcapng reader and writer, every protocol dissector, the SIP/SDP/RTP
  parsing and the G.711 decoding are TNT's own, written from the published specifications
  (IETF RFCs, IEEE and ITU-T standards). No GPL code — no Wireshark, libpcap, dpkt or scapy — is
  used anywhere, which is what lets TNT ship all of it under the MIT licence.

## Pro AV

The Pro AV page is for networks carrying professional audio: Dante, AES67, Ravenna, SMPTE
ST 2110, Q-LAN, AVB. All of them discover and clock themselves over multicast, which means a
PC that does nothing but listen can answer most of what an integrator wants to know before
touching a cable.

**It only listens.** A scan joins four multicast groups on one adapter and reads what is
already being announced to every device on the VLAN. The one thing it sends is the mDNS
question the protocol exists to answer — and rather than guessing at service names it asks the
DNS-SD meta-query, "list the service types you have", so the network says what it has. Nothing
is port-scanned, probed or connected to. That is deliberate: these networks carry live shows.

What a scan gives you:

* **Devices** — merged from every source that saw them (mDNS, PTP, the stream announcements
  and the ARP table), with name, model, firmware, maker and what each one offers.
* **Streams** — every announced stream with its multicast group, encoding, sample rate,
  channel count and packet time, and the bandwidth it really costs on the wire (computed, not
  announced: the payload plus the RTP/UDP/IP/Ethernet overhead at the real packet rate).
* **The clock** — who the grandmaster is and what it is locked to, how many boundary clocks
  are between it and you, whether a switch is timestamping packets in transit, how evenly sync
  arrives, and which devices are following it. That last one comes free: in the usual multicast
  mode every follower asks the master for the time on the same group, so listening enumerates
  gear that answers nothing else.
* **Findings** — the checks a competent integrator runs by hand, worst first, each saying what
  it measured and what to do about it.
* **Two diagrams** — the PTP clock tree and the stream flow map.

It also reads frames off the adapter for the three checks a socket cannot make: whether the
VLAN has an **IGMP querier** (no querier plus snooping is the classic "the audio stopped two
minutes after it all looked fine" fault), whether multicast is being **flooded** to this port,
and whether the traffic still carries its **QoS marking**. That part needs Windows administrator
rights, which the background service has; where it cannot run, the scan says those were not
checked — never that they passed. There is no option to skip it: a tech wants the whole
picture, and it costs about 4% of one processor core while a scan is running. If the listen
cannot keep up with a heavily flooded port it says so, and the numbers it does report are
marked as a lower bound rather than passed off as complete.

**What it will not do is draw a wiring diagram.** One PC hears LLDP from its own switch port
and nothing about anyone else's, and reading a switch's MAC table needs SNMP or a login, so
which device is in which port cannot be known from here. The clock tree and the flow map are
drawn because they *are* derivable from what arrives; a picture of the patching would be
invention, and the page says so where the diagram is.

## SIP

The SIP page answers the question a phone install actually turns on: will calls work here, and
when they do not, whose problem is it. Four cards, in the order the questions get asked.

**Qualify the line.** Nothing new is measured — the rating is read out of what TNT has been
collecting anyway, the ping history for this network and the last speed test on it, scored with
the same call-quality model the Speed page uses. What matters is that it is split. A good
gateway with a bad internet leg is a call to the ISP, with the numbers to quote. A bad gateway
is the switch, the cabling or Wi-Fi, and it is in the building. One combined number would hide
exactly the distinction that decides who fixes it. Name your PBX, SBC or registrar and it is
graded as its own leg as well, on the route the calls really take rather than to some general
internet host.

Above the legs sit the three numbers a phone system's support desk will ask you for: a **MOS**, the **average
delay** and the **average jitter**. They come from whichever leg is weakest, not from adding the legs up or
averaging them — a ping to the internet already crosses the gateway, so adding would count the same milliseconds
twice, and averaging a good leg with a bad one hides the bad one. The card says which leg they came from, because
a MOS with no idea which hop produced it is a number to argue about rather than act on.

A leg without enough history behind it is reported ungraded, with the reason. A rating computed
from four minutes of data would look exactly as convincing as a real one.

At most three targets of each kind are graded, in the order they are listed on the Ping page, so a
site with twenty ping targets gets an answer rather than a list — and the rating says how many it
left out.

**Is something rewriting your SIP?** A SIP ALG is a router "helping" by editing SIP as it goes
past, and it is behind a large share of one-way audio and calls that will not complete. TNT
sends an OPTIONS to your own phone system from source port 5060 and again from an ordinary port,
and compares what the server echoes back with what went out. It can do that because the protocol
requires it: a response repeats Via, Call-ID, CSeq and From exactly as received, since that is
how it finds its way home. Anything different was changed in transit. Most of these boxes only
engage on port 5060, so a rewritten probe from 5060 beside a clean one from another port is both
the diagnosis and the workaround.

The verdicts stay honest. "Clean" means nothing rewrote what TNT sent, which is as much as a
probe can show — not that there is no ALG anywhere. A server that never answered gets its own
verdict rather than being counted as a pass. SIP over TLS is moot: nothing in the path can read
it, so nothing in the path can rewrite it.

**Will the audio get back?** TNT asks two public STUN servers what address and port they see,
from one local socket. If they see the same port, this NAT keeps one mapping per source and
voice is fine. If they see two different ports, every destination gets its own mapping — a phone
system told about one of them sends its audio to the other, and that is the classic one-way-audio
NAT. There is a second, slower test behind its own button: get a mapping, go quiet, and ask again
after 15, 30, 60, 120 and 240 seconds. A NAT that forgets a UDP binding in 30 seconds, with a
phone that re-registers every few minutes, leaves a window where an inbound call has nowhere to
arrive.

**What actually happened on the call?** Browse to a capture — the TNT window opens its own file
dialog, so there is no path to type — and every SIP call in it is listed; click
one and you get the flow as a ladder — INVITE, 100 Trying, 180 Ringing, 200 OK, the ACK, the RTP
streams, the BYE — colour-coded so a 4xx or a missing ACK stands out. Click any row for that
packet's headers in the order they were sent, with the SDP body where the audio addresses and
codecs are agreed. You can play the call, or one direction on its own, which is how one-way audio
is confirmed by ear rather than by argument.

Load a second capture from the other side of the network and the two are merged. They are matched
on Call-ID, which is globally unique and travels unchanged, not on the time of day; the clock
difference between the two captures is then measured from the messages that appear in both and
stated, so the ladder can be read on one timeline. A header that differs between the two sides is
the one conclusive proof that something in the middle rewrote it: the message went in one way and
came out another. Through a session border controller each side has its own Call-ID, and the
calls are paired on the numbers and overlapping lifetimes instead.

The call-quality lines and the Zoom / Teams checks that used to sit on the Speed page live here
now — they are about calls, and this is the calls page. The bufferbloat grade stays on Speed,
where the measurement is made, and is repeated here only when the line buffers badly enough to
break a call, which is the complaint that arrives as "the phones are random".

## Security model (local)

* The API binds **127.0.0.1 only** (`api.host` cannot be set to anything else) and rejects
  requests whose `Host` header is not a loopback name (DNS-rebinding protection) as well as
  state-changing requests that carry a foreign `Origin` / `Sec-Fetch-Site: cross-site`
  (browser CSRF protection). Scripts on the same machine (curl, PowerShell) work as before.
* `%ProgramData%\TNT` is locked down by the installer (SYSTEM + Administrators full control,
  Users read-only); the tray client never writes there (`%LOCALAPPDATA%\TNT` is its folder).
* **Saved Wi-Fi passwords are shown only to a Windows administrator.** The Tools page can list
  every WLAN profile this PC has joined; the network names are open to any local user, but the
  saved keys are revealed only after the service confirms that the process asking (over the
  loopback API) runs under a Windows administrator account, elevated or not. A standard user
  gets the list with the keys withheld. A browser request for the keys from any page that the
  TNT service did not serve is refused as well, whoever runs the browser. The keys are never
  sent anywhere off `127.0.0.1`.
* **Packet capture is shown only to a Windows administrator.** Raw traffic can carry other users'
  sessions and cleartext credentials, so every capture route — starting one, the packet list, a
  packet's detail, the SIP calls, opening a capture file and the file download — is refused unless
  the service confirms that the process asking runs under a Windows administrator account, elevated
  or not, and it fails closed when it cannot tell. A browser request from a page the TNT service did
  not serve is refused first. That gate is also what makes opening a capture file by its path safe:
  the service reads the file for an administrator, who could already read it. The dashboard's capture
  tile carries only counts and the adapter's name, never a packet. The capture files live in a folder
  only SYSTEM and Administrators can open.
* Speed tests and discovery are built in: the service runs no third-party program, and no
  setting names an executable for it to run.
* Monitoring holes are recorded honestly: sleep/hibernate (detected as a >90 s heartbeat
  silence), a paused monitor and a stopped service all become grey "not monitoring" spans
  on the timeline instead of a green bar or an outage that silently absorbs the gap.
* `python -m tnt --console` refuses to start against the installed service's live database
  unless `--data-dir` (or `TNT_DATA_DIR`) points elsewhere.

## Troubleshooting

* **Window says "Can't reach the TNT service"** — open `services.msc`, find *TNT - TEC
  Network Tool Service* (`TNTService`) and start it; check that it is set to *Automatic*.
  The service log `%ProgramData%\TNT\logs\tnt-service.log` says why it stopped.
* **Port conflict** — if another program holds 7130 the log shows `port 7130 is in use`;
  find the owner with `netstat -ano | findstr :7130` (the message says the same and how to
  move TNT). Either free the port or set `api.port` in `config.json` or the `TNT_PORT`
  environment variable (restart the service) and run the client with `--port N`.
* **Tray icon missing / window blank** — check `%LOCALAPPDATA%\TNT\client.log`. A window whose
  browser died (a crash, a display-driver reset, a Windows restart that was abandoned)
  restarts itself within about 10 s, and opening TNT from the tray always restarts it. A
  window that stays blank means the WebView2 runtime is missing, broken or older than
  version 111 (the log says which after 45 s, and a tray notification tells the user):
  install it from <https://developer.microsoft.com/microsoft-edge/webview2/> or re-run setup
  while online.
* **Only one client runs at a time** — starting `TNT.exe` again just brings the existing
  window to the front.
* **Diagnostics page** (tray menu → *Diagnostics*) shows service uptime, threads, ping
  worker health, database size, speed-test backend availability, the last 100 log lines and
  a *Copy all* button — attach that when reporting a problem.
* **Ethernet port left on 172.16.4.100** — the DHCP server tool changed it and could not
  put it back (service killed mid-way). Start the service: it restores the port at start.
  If the service cannot start, `netsh interface ipv4 set address name="Ethernet" source=dhcp`
  in an elevated prompt does the same (a reboot also undoes it). The tool only ever changes
  the address source; DNS settings are left as they were.
* **Reset** — stop the service, delete `%ProgramData%\TNT\tnt.db` (history is lost) or
  `config.json` (settings back to defaults), start the service.
