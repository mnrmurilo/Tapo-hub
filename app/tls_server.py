"""Threaded HTTPS listener: a stalled TLS client cannot block new connections."""
from http.server import ThreadingHTTPServer
import threading


class TLSHTTPServer(ThreadingHTTPServer):
    handshake_timeout = 10
    request_timeout = 15

    def __init__(self, address, handler, context):
        self.context = context
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler)

    def get_request(self):
        connection, peer = super().get_request()
        try:
            connection.settimeout(self.handshake_timeout)
            # The accept loop must never perform TLS network I/O.
            return self.context.wrap_socket(connection, server_side=True,
                                            do_handshake_on_connect=False), peer
        except BaseException:
            connection.close()
            raise

    def process_request(self, request, peer):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, peer)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, peer):
        try:
            try:
                request.do_handshake()
            except OSError:
                self.shutdown_request(request)
                return
            request.settimeout(self.request_timeout)
            super().process_request_thread(request, peer)
        finally:
            self.slots.release()
