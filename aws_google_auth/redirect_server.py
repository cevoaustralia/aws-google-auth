#!/usr/bin/env python
"""
This HTTP server can be run on a server, and redirects the SAMLResponse to 127.0.0.1 so the command can capture it
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class RedirectServerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(307)
        self.send_header('location', 'http://127.0.0.1:4589/')
        self.end_headers()

def start_redirect_server(port):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = HTTPServer(server_address, RedirectServerHandler)
    logging.info('Starting http redirect server on: %s', port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping http redirect server')
