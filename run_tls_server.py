#!/usr/bin/env python3

import http.server
import ssl

HOST = 'localhost'
PORT = 4443

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        
        # Just respond with a Hello message for testing
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello from Python HTTPS Server\n")

def main():
    httpd = http.server.HTTPServer((HOST, PORT), SimpleHandler)
    
    # Wrap the socket with TLS using our self-signed cert and key
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile="cert.pem",
        keyfile="key.pem",
        ssl_version=ssl.PROTOCOL_TLS_SERVER
    )
    
    print(f"Serving on https://{HOST}:{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()