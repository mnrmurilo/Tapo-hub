from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_server import TLSHTTPServer


class Reply(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


class ListenerTests(unittest.TestCase):
    def test_stalled_and_invalid_tls_do_not_block_healthy_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
                    .sign(key, hashes.SHA256()))
            (root/'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (root/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'cert', root/'key')
            server = TLSHTTPServer(('127.0.0.1', 0), Reply, context)
            server.handshake_timeout = 1
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stalled = socket.create_connection(server.server_address, timeout=3)
            try:
                with socket.create_connection(server.server_address, timeout=3) as invalid:
                    invalid.sendall(b'not TLS\r\n')
                    self.assertEqual(invalid.recv(1), b'')
                with socket.create_connection(server.server_address, timeout=0.5) as raw:
                    with ssl._create_unverified_context().wrap_socket(raw, server_hostname='localhost') as healthy:
                        healthy.sendall(b'GET / HTTP/1.0\r\n\r\n')
                        result = b''
                        while data := healthy.recv(4096):
                            result += data
                self.assertIn(b'200 OK', result)
                self.assertTrue(result.endswith(b'ok'))
                # The idle peer must also be disconnected after its handshake deadline.
                self.assertEqual(stalled.recv(1), b'')
            finally:
                stalled.close()
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
