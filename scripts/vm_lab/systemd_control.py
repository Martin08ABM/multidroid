"""VM-only independent control process, kept in its own systemd unit."""
import os
from pathlib import Path
import time

Path("/run/multidroid-control.pid").write_text(str(os.getpid()))
while True:
    time.sleep(60)
