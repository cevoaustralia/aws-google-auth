#!/usr/bin/env python
"""
This HTTP server for capturing the SAMLResponse that is redirected to 127.0.0.1
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

from aws_google_auth import util

class LoginServer(HTTPServer):
    post_data = {}


class LoginServerHandler(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('content-type', 'text/html')
        self.end_headers()
        self.wfile.write("""
           <html>
           <head><title>Success</title></head>
           <body>
           Check your console
           <script>window.close()</script>
           </body>
           </html>
        """.encode("utf-8"))

    def do_POST(self):
        self.server.post_data = util.Util.parse_post(self)
        logging.debug("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), self.server.post_data)

        self._set_response()
