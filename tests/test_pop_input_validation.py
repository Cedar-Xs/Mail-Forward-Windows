"""POP3 credentials cannot inject commands, including through direct callers."""
from dataclasses import replace
import threading
import unittest
from unittest.mock import MagicMock, patch

from mailclient.cancellation import Cancelled
from mailclient.config import Config, ConfigError
from mailclient.transports import TransportError, pop_session


class PopInputValidationTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(pop_host="pop.example.test", pop_user="user@example.test",
                          pop_password="fake-private-password", wecom_enabled=False,
                          remember_credentials=False)

    def test_config_rejects_each_line_break_in_account_or_password(self):
        for field in ("pop_user", "pop_password"):
            for newline in ("\r", "\n", "\r\n"):
                cfg = replace(self.cfg, **{field: "fake-private-value" + newline + "DELE 1"})
                for require_channels in (False, True):
                    with self.subTest(field=field, newline=repr(newline), channels=require_channels):
                        with self.assertRaises(ConfigError) as caught:
                            cfg.validate(require_channels=require_channels)
                        self.assertIn("不能包含换行符", str(caught.exception))
                        self.assertNotIn("fake-private-value", str(caught.exception))
                        self.assertNotIn("DELE", str(caught.exception))

    def test_direct_sessions_reject_injection_before_any_connection(self):
        for field in ("pop_user", "pop_password"):
            for newline in ("\r", "\n", "\r\n"):
                for security in ("SSL/TLS", "STARTTLS", "不加密"):
                    cfg = replace(self.cfg, pop_security=security,
                                  **{field: "fake-private-value" + newline + "DELE 1"})
                    with self.subTest(field=field, newline=repr(newline), security=security), \
                         patch("mailclient.transports.poplib.POP3_SSL") as encrypted, \
                         patch("mailclient.transports.poplib.POP3") as plain, \
                         patch("mailclient.transports.pop_context") as tls:
                        with self.assertRaises(TransportError) as caught:
                            with pop_session(cfg):
                                self.fail("Invalid credentials must never open a mailbox")
                        self.assertEqual(caught.exception.stage, "login")
                        self.assertIn("不能包含换行符", str(caught.exception))
                        self.assertNotIn("fake-private-value", str(caught.exception))
                        self.assertNotIn("DELE", str(caught.exception))
                        encrypted.assert_not_called()
                        plain.assert_not_called()
                        tls.assert_not_called()

    def test_valid_password_spaces_are_preserved_by_validation_and_wire_call(self):
        cfg = replace(self.cfg, pop_password="  fake password with spaces  ")
        cfg.validate(require_channels=False)
        self.assertEqual(cfg.pop_password, "  fake password with spaces  ")
        connection = MagicMock()
        with patch("mailclient.transports.poplib.POP3_SSL", return_value=connection):
            with pop_session(cfg) as mailbox:
                self.assertIs(mailbox, connection)
        connection.user.assert_called_once_with(cfg.pop_user)
        connection.pass_.assert_called_once_with("  fake password with spaces  ")
        connection.quit.assert_called_once()

    def test_cancellation_still_takes_priority_before_invalid_input(self):
        stop = threading.Event()
        stop.set()
        cfg = replace(self.cfg, pop_password="fake\r\nDELE 1")
        with patch("mailclient.transports.poplib.POP3_SSL") as encrypted, \
             patch("mailclient.transports.poplib.POP3") as plain:
            with self.assertRaises(Cancelled):
                with pop_session(cfg, stop_event=stop):
                    self.fail("Cancelled sessions must never open a mailbox")
        encrypted.assert_not_called()
        plain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
