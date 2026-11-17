"""Reject ambiguous UIDL mappings and size SMTP messages as actually serialized."""
from email.generator import BytesGenerator
from io import BytesIO
import unittest
from unittest.mock import Mock, patch

from mailclient.config import Config
from mailclient.parsing import Mail
from mailclient.transports import TransportError, build_forward, send_smtp, uidl_list


class UidlValidationTests(unittest.TestCase):
    def test_zero_and_duplicate_message_numbers_are_rejected(self):
        for lines in ([b"0 uid-zero"], [b"1 uid-first", b"1 uid-second"],
                      [b"01 uid-first", b"1 uid-second"]):
            with self.subTest(lines=lines):
                connection = Mock()
                connection.uidl.return_value = (b"+OK", lines, 0)
                with self.assertRaises(TransportError) as rejected:
                    uidl_list(connection)
                self.assertEqual(rejected.exception.stage, "mailbox")

    def test_sparse_positive_message_numbers_remain_supported(self):
        connection = Mock()
        connection.uidl.return_value = (b"+OK", [b"9 uid-nine", b"3 uid-three"], 0)
        self.assertEqual(uidl_list(connection), [(3, "uid-three"), (9, "uid-nine")])


class SmtpSizeValidationTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(smtp_user="user@example.test", smtp_to="receiver@example.test")
        self.mail = Mail("CRLF size check", plain="first line\nsecond line\n" * 4)
        self.message = build_forward(self.cfg, self.mail)
        serialized = BytesIO()
        # Match the BytesGenerator / CRLF serialization used by send_message.
        BytesGenerator(serialized).flatten(self.message, linesep="\r\n")
        self.smtp_size = len(serialized.getvalue())

    def test_crlf_over_limit_is_rejected_before_opening_smtp(self):
        lf_size = len(self.message.as_bytes())
        self.assertGreater(self.smtp_size, lf_size)
        # A small limit between the two real MIME encodings exposes the same
        # LF undercount without allocating a 25 MiB regression-test message.
        with patch("mailclient.transports.SMTP_MAX_MESSAGE_BYTES", lf_size), \
             patch("mailclient.transports.build_forward", return_value=self.message), \
             patch("mailclient.transports.smtp_session") as session:
            with self.assertRaises(TransportError) as rejected:
                send_smtp(self.cfg, self.mail)
        self.assertEqual(rejected.exception.stage, "smtp")
        session.assert_not_called()

    def test_message_at_exact_crlf_limit_is_sent_once(self):
        with patch("mailclient.transports.SMTP_MAX_MESSAGE_BYTES", self.smtp_size), \
             patch("mailclient.transports.build_forward", return_value=self.message), \
             patch("mailclient.transports.smtp_session") as session:
            connection = session.return_value.__enter__.return_value
            connection.send_message.return_value = {}
            send_smtp(self.cfg, self.mail)
        connection.send_message.assert_called_once_with(self.message, to_addrs=self.cfg.recipients)


if __name__ == "__main__":
    unittest.main()
