"""Loopback-only TLS terminator for Secure test cookies under APP_ENV=testing.

Forwards solely to the team01 artisan server at 127.0.0.1:18101. Never logs
headers, cookies, tokens, bodies, or credentials.
"""
import http.client
import http.server
import pathlib
import ssl
import sys

runtime = pathlib.Path(sys.argv[1]).resolve(strict=True)
cert = runtime / "team01-cert.pem"
key = runtime / "team01-key.pem"
if not cert.is_file() or not key.is_file():
    raise RuntimeError("team01 temporary TLS certificate missing")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle_request(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in ("connection", "keep-alive", "proxy-connection", "transfer-encoding")}
        headers["Connection"] = "close"
        connection = http.client.HTTPConnection("127.0.0.1", 18101, timeout=20)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in ("connection", "keep-alive", "proxy-connection", "transfer-encoding", "content-length"):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        finally:
            connection.close()
            self.close_connection = True

    do_GET = handle_request
    do_POST = handle_request
    do_PATCH = handle_request
    do_DELETE = handle_request
    do_OPTIONS = handle_request


server = http.server.ThreadingHTTPServer(("127.0.0.1", 18102), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=str(cert), keyfile=str(key))
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
