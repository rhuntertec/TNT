TNT - TEC Network Tool
by Total Electronics

TNT is a Windows network monitor and field toolkit. A Windows service does the
monitoring from the moment the PC boots, and a tray icon opens the dashboard in a
window. Everything runs on the PC itself: the dashboard is served on 127.0.0.1 only,
works while the internet is down, and TNT sends no telemetry.


FEATURES

  Network info  Adapters, addresses, gateways and DNS, plus a live link map
                (PC -> gateway -> internet) with the router's public IP.
  Ping          Continuous pings to the gateway, 1.1.1.1, totalelectronics.com and
                any host you add, with latency and loss history.
  Outages       Automatic outage detection (per target and total), a timeline, and
                missed pings / missed % for each outage.
  Speed         Scheduled internet speed tests (Cloudflare, fast.com) with history
                and time-of-day patterns.
  Discovery     LAN scan: open ports, MAC vendor and device type (router, camera,
                phone, DW server, Wi-Fi).
  Tools         DHCP server for gear with no address, traceroute with a path map,
                LAN throughput test between TNT PCs, subnet calculator, and saved
                Wi-Fi networks (passwords are shown to Windows administrators only).

Also: PDF reports, a diagnostics page, and light and dark themes.


REQUIREMENTS

  - 64-bit Windows 10 version 1809 or newer, or Windows 11
  - .NET Framework 4.7.2 or later (built into those Windows versions)
  - Microsoft Edge WebView2 Runtime 111 or later (setup installs it when online)
  - Administrator rights to install


INSTALL

  1. Download TNT-Setup-<version>.exe from the Releases page and run it.
     Builds that are not code-signed yet trigger a SmartScreen warning:
     choose "More info", then "Run anyway".
  2. Open TNT from the tray icon or the Start menu.

  Program files: C:\Program Files\TNT
  Settings, database, logs and reports: C:\ProgramData\TNT
  Uninstall from Settings > Apps.

  Network use:
    127.0.0.1:7130   dashboard and API (this PC only)
    UDP 7132         finding other TNT PCs on the LAN (can be switched off in Tools)
    TCP 7133         LAN throughput test between TNT PCs
    UDP 67           the DHCP server, only while it is switched on
  TNT adds the Windows Firewall rules these features need.


BUILD FROM SOURCE

  Needs 64-bit Python 3.12 and Inno Setup 6.3 or newer. From the repository root in
  PowerShell:

    powershell -ExecutionPolicy Bypass -File installer\build.ps1 -SkipSign

  The script creates .venv, installs requirements.txt, runs the tests, builds
  TNTService.exe and TNT.exe with PyInstaller, and writes the installer to
  installer\output\TNT-Setup-<version>.exe.

  Development:
    py -3.12 -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
    .venv\Scripts\python -m pytest
    .venv\Scripts\python -m tnt --console --port 7135     monitoring engine in a console
    .venv\Scripts\python client\tray.py --port 7135       tray and window against it
    .venv\Scripts\python tools\mock_api.py --port 7136    UI with a fake API, no engine


LICENSE

  MIT License, Copyright (c) 2026 Total Electronics. See LICENSE.
  Bundled third-party components and their licences: THIRD-PARTY-NOTICES.txt.
