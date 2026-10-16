"""A deliberately tiny HTTP service: the same code runs in every Dockerfile stage.

GET /healthz            liveness probe, always {"status": "ok"}
GET /sign?msg=hello     a signed, tamper-evident token for msg (uses itsdangerous so the
                        image has one real third-party dependency to install and cache)
"""
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from itsdangerous import URLSafeSerializer

PORT = int(os.environ.get("PORT", "8080"))
# A fresh secret per process unless one is injected. Never bake a secret into an image.
SIGNER = URLSafeSerializer(os.environ.get("HARDLAB_SECRET") or os.urandom(32).hex())


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            self._send(200, {"status": "ok"})
        elif url.path == "/sign":
            msg = parse_qs(url.query).get("msg", [""])[0]
            self._send(200, {"msg": msg, "token": SIGNER.dumps(msg)})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):  # logs go to stdout, one line each
        print("%s %s" % (self.address_string(), fmt % args), flush=True)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)

    # PID 1 in a container only gets the signals it installs handlers for. Without this,
    # `docker stop` waits the full grace period and then kills the process.
    def stop(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print("listening on :%d" % PORT, flush=True)
    server.serve_forever()
    print("stopped cleanly", flush=True)


if __name__ == "__main__":
    main()
