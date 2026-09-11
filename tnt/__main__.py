"""``python -m tnt`` entry point: delegates to :func:`tnt.service.main`."""
from __future__ import annotations

import sys

try:
    from tnt.service import main          # normal package import (also the frozen exe,
except ImportError:                       # where PyInstaller runs this file as a script)
    from .service import main             # type: ignore[no-redef]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
