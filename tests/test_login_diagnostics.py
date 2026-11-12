"""Login failure details must be useful without exposing echoed credentials."""
from dataclasses import replace
import poplib
import threading
import traceback
import unittest
from unittest.mock import MagicMock, patch

from mailclient.cancellation import Cancelled
from mailclient.config import Config
from mailclient.transports import TransportError, diagnose, pop_session


class LoginDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(pop_host="pop.example.test", pop_user="user@example.test",
                          pop_password="fake-password", wecom_enabled=False,
                          remember_credentials=False)

    def failure(self, reply, command="PASS", cfg=None):
        connection = MagicMock()
        method = connection.user if command == "USER" else connection.pass_
        method.side_effect = poplib.error_proto(reply)
        with patch("mailclient.transports.poplib.POP3_SSL", return_value=connection):
            with self.assertRaises(TransportError) as caught:
                with pop_session(cfg or self.cfg):
                    self.fail("Rejected authentication must not yield a mailbox")
        return connection, caught.exception

    def test_user_rejection_identifies_account_step_and_does_not_send_password(self):
        connection, error = self.failure(b"-ERR [AUTH] POP3 access disabled", "USER")
        self.assertEqual(error.stage, "login")
        self.assertIn("USER", str(error))
        self.assertIn("账号提交", str(error))
        self.assertIn("-ERR [AUTH] POP3 access disabled", str(error))
        connection.pass_.assert_not_called()
        connection.quit.assert_called_once()

    def test_distinct_password_rejections_reach_both_status_and_log(self):
        for reply in (b"-ERR invalid password", b"-ERR client authorization required",
                      b"-ERR [IN-USE] mailbox locked", b"-ERR EOF"):
            with self.subTest(reply=reply):
                connection = MagicMock()
                connection.pass_.side_effect = poplib.error_proto(reply)
                events = []
                with patch("mailclient.transports.socket.getaddrinfo"), \
                     patch("mailclient.transports.socket.create_connection"), \
                     patch("mailclient.transports.poplib.POP3_SSL", return_value=connection), \
                     patch("mailclient.transports.send_wecom") as webhook, \
                     patch("mailclient.transports.send_smtp") as smtp:
                    result = diagnose(self.cfg, lambda kind, **data: events.append((kind, data)),
                                      mailbox_only=True)
                self.assertFalse(result.mailbox_ok)
                for kind in ("status", "log"):
                    texts = [data["text"] for event_kind, data in events
                             if event_kind == kind and data.get("level", "").lower() == "error"]
                    self.assertEqual(len(texts), 1)
                    self.assertIn("PASS", texts[0])
                    self.assertIn("密码验证", texts[0])
                    self.assertIn(reply.decode("ascii"), texts[0])
                webhook.assert_not_called()
                smtp.assert_not_called()
                connection.quit.assert_called_once()

    def test_chinese_reply_is_readable_in_utf8_and_gb18030(self):
        for encoding in ("utf-8", "gb18030"):
            with self.subTest(encoding=encoding):
                _, error = self.failure("-ERR 客户端权限未开启".encode(encoding))
                self.assertIn("-ERR 客户端权限未开启", str(error))
                self.assertNotIn("\\x", str(error))

    def test_credentials_are_hidden_before_the_exception_or_traceback_is_exposed(self):
        cfg = replace(self.cfg, pop_password="口令'\\secret", smtp_user="sender@example.test",
                      smtp_password="口令'\\secret-longer", smtp_host="smtp.example.test",
                      wecom_webhook="https://example.test/send?key=FAKE-WEBHOOK-KEY")
        values = (cfg.pop_user, cfg.pop_host, cfg.pop_password, cfg.smtp_user,
                  cfg.smtp_host, cfg.smtp_password, cfg.wecom_webhook)
        reply = "-ERR [AUTH] " + " | ".join(values) + " ?key=OTHER-ROBOT-KEY"
        replies = [reply, reply.encode("utf-8"), reply.encode("gb18030"),
                   b"\xff" + reply.encode("utf-8")]
        for response in replies:
            with self.subTest(response_type=type(response).__name__):
                _, error = self.failure(response, cfg=cfg)
                rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
                for value in (*values, "secret-longer", "FAKE-WEBHOOK-KEY", "OTHER-ROBOT-KEY"):
                    self.assertNotIn(value, str(error))
                    self.assertNotIn(value, rendered)
                self.assertIn("[AUTH]", str(error))
                self.assertTrue(error.__suppress_context__)

    def test_status_and_log_also_hide_server_echoed_credentials(self):
        connection = MagicMock()
        connection.pass_.side_effect = poplib.error_proto(
            f"-ERR rejected {self.cfg.pop_user} {self.cfg.pop_password}".encode())
        events = []
        with patch("mailclient.transports.socket.getaddrinfo"), \
             patch("mailclient.transports.socket.create_connection"), \
             patch("mailclient.transports.poplib.POP3_SSL", return_value=connection):
            diagnose(self.cfg, lambda kind, **data: events.append((kind, data)), mailbox_only=True)
        texts = " ".join(data.get("text", "") for _, data in events)
        self.assertNotIn(self.cfg.pop_user, texts)
        self.assertNotIn(self.cfg.pop_password, texts)
        self.assertIn("-ERR rejected", texts)

    def test_server_normalized_account_and_host_case_are_also_hidden(self):
        reply = f"-ERR [AUTH] {self.cfg.pop_user.upper()} at {self.cfg.pop_host.upper()}"
        for response in (reply, reply.encode("ascii"), b"\xff" + reply.encode("ascii")):
            with self.subTest(response_type=type(response).__name__):
                _, error = self.failure(response)
                self.assertNotIn(self.cfg.pop_user.casefold(), str(error).casefold())
                self.assertNotIn(self.cfg.pop_host.casefold(), str(error).casefold())
                self.assertIn("[AUTH]", str(error))

    def test_control_characters_cannot_create_extra_log_lines_and_long_replies_are_bounded(self):
        reply = "-ERR [AUTH]\r\nforged log\t\x00\x1b\u202e\u2028" + "x" * 2000
        _, error = self.failure(reply.encode("utf-8"))
        message = str(error)
        self.assertTrue(message.isprintable())
        self.assertLessEqual(len(message), 800)
        self.assertIn("[AUTH]", message)

    def test_empty_or_undecodable_reply_does_not_break_failure_reporting(self):
        for reply in (b"", "", b"-ERR \xff\xfe\x80"):
            with self.subTest(reply=reply):
                connection, error = self.failure(reply)
                self.assertEqual(error.stage, "login")
                self.assertIn("服务器响应", str(error))
                self.assertGreater(len(str(error).split("服务器响应：", 1)[1]), 0)
                connection.quit.assert_called_once()

    def test_cancellation_still_takes_priority_over_a_rejected_password(self):
        stop = threading.Event()
        connection = MagicMock()
        def reject(password):
            stop.set()
            raise poplib.error_proto(b"-ERR cancelled login")
        connection.pass_.side_effect = reject
        with patch("mailclient.transports.poplib.POP3_SSL", return_value=connection):
            with self.assertRaises(Cancelled):
                with pop_session(self.cfg, stop_event=stop):
                    self.fail("Cancelled login must not yield a mailbox")
        connection.close.assert_called_once()

    def test_successful_login_preserves_credentials_and_existing_flow(self):
        cfg = replace(self.cfg, pop_password=" password with spaces ")
        connection = MagicMock()
        with patch("mailclient.transports.poplib.POP3_SSL", return_value=connection):
            with pop_session(cfg) as mailbox:
                self.assertIs(mailbox, connection)
        connection.user.assert_called_once_with(cfg.pop_user)
        connection.pass_.assert_called_once_with(cfg.pop_password)
        connection.quit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
