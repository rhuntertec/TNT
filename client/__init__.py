"""TNT client package: the tray icon + WebView2 window (``TNT.exe``).

The client never touches the service's data directory or database. It talks to
the service exclusively over the loopback HTTP API (``http://127.0.0.1:7130``)
and keeps its own small log in ``%LOCALAPPDATA%\\TNT\\client.log``.

Modules
-------
``client.icons``        Pillow drawing of the dynamite-stick icon (+ status dot).
``client.tray``         The application: single instance, wait-for-service, pywebview
                        window, pystray icon, JS bridge.
``client.wifi_survey``  The WiFi tile's survey (WLAN API as the signed-in user, who can grant
                        the location access Windows requires for BSSID lists), its store and
                        scanner thread; reaches the UI through the JS bridge only.
``client.wifi_ies``     Pure 802.11 information-element parsing for the survey.
"""
