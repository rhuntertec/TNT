TNT - TEC Network Tool
by Total Electronics

TNT is a Windows network monitor and field toolkit. A Windows service does the
monitoring from the moment the PC boots, and a tray icon opens the dashboard in a
window. Everything runs on the PC itself: the dashboard is served on 127.0.0.1 only,
works while the internet is down, and TNT sends no telemetry.


FEATURES

  Network info  Adapters, addresses, gateways and DNS, plus a live link map
                (PC -> gateway -> internet) with the router's public IP and its
                internet provider and city (IP Geolocation by DB-IP). Follows the
                PC onto another network within seconds and points out adapter
                problems such as no DHCP answer or a gateway outside the subnet.
  Ping          Continuous pings to the gateway, 1.1.1.1, totalelectronics.com and
                any host you add, with latency and loss history.
  Outages       Automatic outage detection (per target and total), a timeline, and
                missed pings / missed % for each outage.
  Speed         Scheduled internet speed tests (Cloudflare, fast.com) with history
                and time-of-day patterns.
  Discovery     LAN scan: open ports, MAC vendor and device type (router, camera,
                phone, DW server, Wi-Fi).
  WiFi          Wi-Fi survey of nearby access points on 2.4, 5 and 6 GHz: channel,
                width, signal over time, security and vendor, with a spectrum chart
                per band. Runs in the TNT window and needs Windows location access.
  Tools         DHCP server for gear with no address, traceroute with a path map
                and hop locations, LAN throughput test between TNT PCs, subnet
                calculator, and saved Wi-Fi networks (passwords are shown to
                Windows administrators only).
  Reports       Full Scan: a speed test, a Discovery scan and a Wi-Fi scan, saved
                with the last 7 days of pings and outages on that site's network
                as a report for the site you name (a network scanned before
                suggests its site). Reports stay on the PC, export as PDF, and
                compare with any other report, for example a known good network.

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
  Settings, database, logs, reports and IP location data: C:\ProgramData\TNT
  Uninstall from Settings > Apps.

  Network use:
    127.0.0.1:7130   dashboard and API (this PC only)
    UDP 7132         finding other TNT PCs on the LAN (can be switched off in Tools)
    TCP 7133         LAN throughput test between TNT PCs
    UDP 67           the DHCP server, only while it is switched on
    HTTPS            download.db-ip.com: IP location data, about 65 MB a month (can be switched off in Settings)
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
  IP location data: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0;
  downloaded by the service, not included in the installer.
