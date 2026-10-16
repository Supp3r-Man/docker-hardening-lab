"""Exit 0 if the service answers /healthz. Used by HEALTHCHECK: no curl, no shell needed."""
import os
import sys
import urllib.request

port = os.environ.get("PORT", "8080")
try:
    with urllib.request.urlopen("http://127.0.0.1:%s/healthz" % port, timeout=2) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
