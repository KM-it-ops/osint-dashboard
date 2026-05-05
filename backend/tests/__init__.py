"""Test package for OSINT dashboard backend."""
from __future__ import annotations

import os

# Avoid live NVD calls and 6h background loop when TestClient runs lifespan.
os.environ.setdefault("OSINT_DISABLE_NVD_POLL", "1")
