"""TNT - TEC Network Tool.

Service-side package. Everything that runs inside the Windows service lives here;
the tray/UI client lives in the sibling ``client`` package and talks to this
package only over the local HTTP API.
"""

__version__ = "1.20.2"
APP_NAME = "TNT"
APP_LONG_NAME = "TNT - TEC Network Tool"
SERVICE_NAME = "TNTService"
SERVICE_DISPLAY_NAME = "TNT - TEC Network Tool Service"
SERVICE_DESCRIPTION = (
    "Background network monitor for TNT (TEC Network Tool): continuous ping "
    "monitoring, outage detection, scheduled internet speed tests and on-demand "
    "network discovery. Serves the local TNT UI on 127.0.0.1."
)
DEFAULT_PORT = 7130  # API + UI; TNT also uses 7132/udp + 7133/tcp (LAN peers) and 7135 (console runs). Overridable via PORT / TNT_PORT env.
