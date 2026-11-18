"""Bounded HTTP/HTTPS listeners; idle clients cannot consume unlimited threads."""
from http.server import ThreadingHTTPServer
import threading


class BoundedHTTPServer(ThreadingHTTPServer):
    request_timeout = 15
    max_connections = 32

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(self.max_connections)
        super().__init__(address, handler)

    def get_request(self):
        connection, peer = super().get_request()
        connection.settimeout(self.request_timeout)
        return connection, peer

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
            super().process_request_thread(request, peer)
        finally:
            self.slots.release()


class TLSHTTPServer(BoundedHTTPServer):
    handshake_timeout = 10

    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def get_request(self):
        connection, peer = super().get_request()
        try:
            connection.settimeout(self.handshake_timeout)
            return self.context.wrap_socket(connection, server_side=True,
                                            do_handshake_on_connect=False), peer
        except BaseException:
            connection.close()
            raise

    def process_request_thread(self, request, peer):
        try:
            request.do_handshake()
        except OSError:
            self.shutdown_request(request)
            self.slots.release()
            return
        request.settimeout(self.request_timeout)
        super().process_request_thread(request, peer)
