"""POP3 initialization owns its socket even when the first reply fails."""
from dataclasses import replace
import io
import poplib
import socket
import socketserver
import ssl
import threading
import unittest
import warnings
from unittest.mock import Mock, patch

from mailclient.config import Config
from mailclient.transports import TransportError, pop_session


class ReplyFile(io.BytesIO):
    def __init__(self, data=b"", read_error=None, close_error=None):
        super().__init__(data)
        self.read_error, self.close_error = read_error, close_error

    def readline(self, *args):
        if self.read_error is not None:
            raise self.read_error
        return super().readline(*args)

    def close(self):
        super().close()
        if self.close_error is not None:
            raise self.close_error


class TrackedSocket:
    def __init__(self, reader, makefile_error=None, shutdown_error=None):
        self.reader = reader
        self.makefile_error, self.shutdown_error = makefile_error, shutdown_error
        self.closed = False
        self.sent = []

    def makefile(self, mode):
        if self.makefile_error is not None:
            raise self.makefile_error
        return self.reader

    def shutdown(self, how):
        if self.shutdown_error is not None:
            raise self.shutdown_error

    def close(self):
        self.closed = True

    def sendall(self, data):
        self.sent.append(data)


class PopResourceTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(pop_host="pop.example.test", pop_user="user@example.test",
                          pop_password="fake-password", remember_credentials=False)

    def test_failed_greeting_closes_clear_and_tls_socket_and_reader_immediately(self):
        cases = ((b"", None), (b"-ERR temporarily unavailable\r\n", None),
                 (b"", TimeoutError("greeting timeout")),
                 (b"", ConnectionResetError("greeting reset")))
        for security in ("不加密", "SSL/TLS"):
            for reply, error in cases:
                with self.subTest(security=security, error=error, reply=reply):
                    reader = ReplyFile(reply, read_error=error)
                    raw = TrackedSocket(reader)
                    context = Mock()
                    context.wrap_socket.return_value = raw
                    with patch("mailclient.transports.poplib.POP3._create_socket", return_value=raw), \
                         patch("mailclient.transports.pop_context", return_value=context):
                        with self.assertRaises(TransportError) as caught:
                            with pop_session(replace(self.cfg, pop_security=security)):
                                self.fail("An invalid greeting must not yield a mailbox")
                    self.assertEqual(caught.exception.stage, "network")
                    if error is not None:
                        self.assertIs(caught.exception.__cause__, error)
                    self.assertTrue(raw.closed)
                    self.assertTrue(reader.closed)
                    self.assertEqual(raw.sent, [])

    def test_socket_is_closed_when_makefile_fails_before_reader_assignment(self):
        for security in ("不加密", "SSL/TLS"):
            with self.subTest(security=security):
                error = OSError("reader creation failed")
                raw = TrackedSocket(None, makefile_error=error)
                context = Mock()
                context.wrap_socket.return_value = raw
                with patch("mailclient.transports.poplib.POP3._create_socket", return_value=raw), \
                     patch("mailclient.transports.pop_context", return_value=context):
                    with self.assertRaises(TransportError) as caught:
                        with pop_session(replace(self.cfg, pop_security=security)):
                            self.fail("A failed reader must not yield a mailbox")
                self.assertIs(caught.exception.__cause__, error)
                self.assertTrue(raw.closed)

    def test_connect_failure_without_a_socket_preserves_original_exception(self):
        for security in ("不加密", "SSL/TLS"):
            with self.subTest(security=security):
                error = ConnectionRefusedError("connect failed")
                with patch("mailclient.transports.poplib.POP3._create_socket", side_effect=error):
                    with self.assertRaises(TransportError) as caught:
                        with pop_session(replace(self.cfg, pop_security=security)):
                            self.fail("A failed connection must not yield a mailbox")
                self.assertIs(caught.exception.__cause__, error)

    def test_tls_handshake_failure_closes_raw_socket_before_self_sock_assignment(self):
        raw = TrackedSocket(None)
        error = ssl.SSLError("TLS handshake failed")
        context = Mock()
        context.wrap_socket.side_effect = error
        with patch("mailclient.transports.poplib.POP3._create_socket", return_value=raw), \
             patch("mailclient.transports.pop_context", return_value=context):
            with self.assertRaises(TransportError) as caught:
                with pop_session(self.cfg):
                    self.fail("A failed TLS handshake must not yield a mailbox")
        self.assertIs(caught.exception.__cause__, error)
        self.assertTrue(raw.closed)

    def test_cleanup_failures_do_not_replace_original_greeting_error(self):
        original = TimeoutError("original greeting failure")
        for failure_location in ("reader", "shutdown"):
            with self.subTest(failure_location=failure_location):
                close_error = RuntimeError("cleanup failure")
                reader = ReplyFile(read_error=original,
                                   close_error=close_error if failure_location == "reader" else None)
                raw = TrackedSocket(reader,
                                    shutdown_error=close_error if failure_location == "shutdown" else None)
                with patch("mailclient.transports.poplib.POP3._create_socket", return_value=raw):
                    with self.assertRaises(TransportError) as caught:
                        with pop_session(replace(self.cfg, pop_security="不加密")):
                            self.fail("A failed greeting must not yield a mailbox")
                self.assertIs(caught.exception.__cause__, original)
                self.assertTrue(raw.closed)
                self.assertTrue(reader.closed)

    def test_successful_initialization_keeps_socket_open_until_normal_quit(self):
        for security in ("不加密", "SSL/TLS"):
            with self.subTest(security=security):
                reader = ReplyFile(b"+OK ready\r\n+OK user\r\n+OK pass\r\n+OK quit\r\n")
                raw = TrackedSocket(reader)
                context = Mock()
                context.wrap_socket.return_value = raw
                with patch("mailclient.transports.poplib.POP3._create_socket", return_value=raw), \
                     patch("mailclient.transports.pop_context", return_value=context):
                    with pop_session(replace(self.cfg, pop_security=security)) as connection:
                        self.assertIs(connection.sock, raw)
                        self.assertFalse(raw.closed)
                self.assertTrue(raw.closed)
                self.assertTrue(reader.closed)
                self.assertEqual(raw.sent, [b"USER user@example.test\r\n", b"PASS fake-password\r\n", b"QUIT\r\n"])

    def test_repeated_real_greeting_disconnects_close_descriptors_without_gc(self):
        class Disconnect(socketserver.BaseRequestHandler):
            def handle(self):
                pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        held_sockets = []
        original_create_connection = socket.create_connection

        def connect(*args, **kwargs):
            client = original_create_connection(*args, **kwargs)
            held_sockets.append(client)  # Retain sockets, so GC cannot hide a leak.
            return client

        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter("always", ResourceWarning)
            with Server(("127.0.0.1", 0), Disconnect) as server:
                thread = threading.Thread(target=server.serve_forever,
                                          kwargs={"poll_interval": 0.01}, daemon=True)
                thread.start()
                try:
                    cfg = replace(self.cfg, pop_host="127.0.0.1", pop_port=server.server_address[1],
                                  pop_security="不加密", timeout_seconds=3)
                    with patch("mailclient.transports.poplib.socket.create_connection", side_effect=connect):
                        for _ in range(12):
                            with self.assertRaises(TransportError):
                                with pop_session(cfg):
                                    self.fail("A disconnect must not yield a mailbox")
                            self.assertEqual(held_sockets[-1].fileno(), -1)
                finally:
                    server.shutdown()
                    thread.join(2)
        self.assertEqual(len(held_sockets), 12)
        self.assertFalse([warning for warning in observed if issubclass(warning.category, ResourceWarning)])


if __name__ == "__main__":
    unittest.main()
