"""TNT client package: the tray icon + WebView2 window (``TNT.exe``).

The client never touches the service's data directory or database. It talks to
the service exclusively over the loopback HTTP API (``http://127.0.0.1:7130``)
and keeps its own small log in ``%LOCALAPPDATA%\\TNT\\client.log``.

Modules
-------
``client.icons``  Pillow drawing of the dynamite-stick icon (+ status dot).
``client.tray``   The application: single instance, wait-for-service, pywebview
                  window, pystray icon, JS bridge.
"""
