"""Health monitoring integrated with mailbox reads, delivery state and loopback HTTP."""
from contextlib import closing, contextmanager
from dataclasses import replace
from http.server import ThreadingHTTPServer
import itertools
from pathlib import Path
import poplib
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch

from mailclient.config import Config
from mailclient.cancellation import Cancelled
from mailclient.engine import Forwarder
from mailclient.health import ConnectivityMonitor
from mailclient.parsing import Mail
from mailclient.state import StateStore
from mailclient.transports import TransportError, diagnose, wecom_payload
from test_client import FakePop, raw_mail
from test_protocols import PopHandler, ThreadedTCP, WebhookHandler, server_instance


class ConnectivityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.cfg = Config(pop_host="pop.example.test", pop_user="user@example.test",
                          pop_password="fake-password", wecom_webhook="https://example.test/?key=FAKE-KEY",
                          remember_credentials=False, keywords="", test_latest_first_run=False)
        self.state = StateStore(self.folder / "state.sqlite3", self.cfg.account_id)
        self.addCleanup(self.state.close)
        self.stop = threading.Event()
        self.sent = []
        self.now = 1_000_000.0
        self.monitor = ConnectivityMonitor(self.cfg, self.state, self.stop, clock=lambda: self.now,
                                           sender=lambda cfg, mail, **kw: self.sent.append(mail))
        self.engine = Forwarder(self.cfg, self.folder, self.stop, connectivity=self.monitor)
        self.monotonic = patch("mailclient.health.time.monotonic", side_effect=itertools.count(10, 10))
        self.monotonic.start()
        self.addCleanup(self.monotonic.stop)

    @contextmanager
    def mailbox(self, pop):
        @contextmanager
        def session(*args):
            yield pop
        with patch("mailclient.engine.pop_session", session):
            yield

    def test_old_delivery_database_upgrades_without_resetting_records_and_isolates_accounts(self):
        path = self.folder / "legacy.sqlite3"
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE accounts(account TEXT PRIMARY KEY, initialized INTEGER);
                CREATE TABLE messages(account TEXT, uid TEXT, wecom INTEGER, smtp INTEGER,
                                      ignored INTEGER, PRIMARY KEY(account,uid));
                INSERT INTO accounts VALUES ('old-account',1);
                INSERT INTO messages VALUES ('old-account','uid-1',1,0,0);
            """)
        first = StateStore(path, "old-account")
        try:
            record = first.load_connectivity()
            record.update(failures=2, success_sent_at=self.now)
            first.save_connectivity(record)
            self.assertTrue(first.initialized)
            self.assertEqual(first.records(), {"uid-1": (True, False, False)})
        finally:
            first.close()
        reopened = StateStore(path, "old-account")
        other = StateStore(path, "other-account")
        try:
            self.assertEqual(reopened.load_connectivity()["failures"], 2)
            self.assertEqual(reopened.load_connectivity()["success_sent_at"], self.now)
            self.assertIsNone(other.load_connectivity()["success_sent_at"])
            self.assertEqual(other.records(), {})
        finally:
            reopened.close()
            other.close()

    def test_stat_and_uidl_must_both_succeed_before_success_is_reported(self):
        pop = MagicMock()
        pop.stat.side_effect = poplib.error_proto(b"-ERR STAT unavailable")
        with self.mailbox(pop), self.assertRaises(TransportError):
            self.engine.poll_once(self.state)
        self.assertEqual(self.monitor.record["failures"], 1)
        self.assertEqual(self.sent, [])
        pop.stat.side_effect = None
        pop.stat.return_value = (0, 0)
        pop.uidl.return_value = (b"+OK", [b"invalid UIDL line"], 0)
        with self.mailbox(pop), self.assertRaises(TransportError):
            self.engine.poll_once(self.state)
        self.assertEqual(self.monitor.record["failures"], 2)
        self.assertEqual(self.sent, [])
        with self.mailbox(FakePop([])):
            self.engine.poll_once(self.state)
        self.assertEqual(self.monitor.record["failures"], 0)
        self.assertEqual([mail.subject for mail in self.sent], ["邮箱连通成功"])

    def test_reopening_sqlite_keeps_success_and_failure_cooldowns_independently(self):
        path = self.folder / "restarted.sqlite3"
        error = TransportError("network", "simulated network outage")
        with closing(StateStore(path, self.cfg.account_id)) as state:
            monitor = ConnectivityMonitor(self.cfg, state, self.stop, clock=lambda: self.now,
                                           sender=lambda cfg, mail, **kw: self.sent.append(mail))
            self.assertTrue(monitor.success(0))
            for _ in range(3):
                monitor.failure(error)
            self.assertEqual([mail.subject for mail in self.sent], ["邮箱连通成功", "邮箱连接异常"])
        self.now += 60
        with closing(StateStore(path, self.cfg.account_id)) as state:
            restarted = ConnectivityMonitor(self.cfg, state, self.stop, clock=lambda: self.now,
                                             sender=lambda cfg, mail, **kw: self.sent.append(mail))
            self.assertIsNone(restarted.success(0))
            for _ in range(3):
                self.assertIsNone(restarted.failure(error))
            self.assertEqual(len(self.sent), 2)
            record = state.load_connectivity()
            self.assertEqual(record["success_sent_at"], self.now - 60)
            self.assertEqual(record["failure_sent_at"], self.now - 60)

    def test_list_cancellation_is_never_counted_as_a_mailbox_failure(self):
        for operation in ("stat", "uidl"):
            with self.subTest(operation=operation):
                pop = MagicMock()
                pop.stat.return_value = (0, 0)
                getattr(pop, operation).side_effect = Cancelled()
                with self.mailbox(pop), self.assertRaises(Cancelled):
                    self.engine.poll_once(self.state)
                self.assertEqual(self.monitor.record["failures"], 0)
                self.assertEqual(self.sent, [])

    def test_mail_retrieval_failure_after_valid_list_does_not_count_as_connection_failure(self):
        self.state.initialize([], False)
        pop = FakePop([("new", raw_mail())])
        with self.mailbox(pop), patch.object(pop, "retr", side_effect=OSError("RETR failed")):
            for _ in range(3):
                with self.assertRaises(TransportError):
                    self.engine.poll_once(self.state)
        self.assertEqual(self.monitor.record["failures"], 0)
        self.assertEqual([mail.subject for mail in self.sent], ["邮箱连通成功"])

    def test_delivery_channel_errors_do_not_raise_a_false_mailbox_alert(self):
        self.cfg.smtp_enabled = True
        self.state.initialize([], False)
        pop = FakePop([("new", raw_mail())])
        with self.mailbox(pop), patch("mailclient.engine.send_wecom", side_effect=OSError("webhook failed")), \
             patch("mailclient.engine.send_smtp", side_effect=OSError("SMTP failed")):
            for _ in range(3):
                self.engine.poll_once(self.state)
        self.assertEqual(self.monitor.record["failures"], 0)
        self.assertEqual([mail.subject for mail in self.sent], ["邮箱连通成功"])
        self.assertEqual(self.state.records()["new"], (False, False, False))

    def test_health_delivery_failure_does_not_stop_mail_processing_or_consume_cooldown(self):
        self.cfg.smtp_enabled = True
        self.state.initialize([], False)
        pop = FakePop([("new", raw_mail())])
        self.monitor.sender = Mock(side_effect=OSError("status webhook failed"))
        with self.mailbox(pop), patch("mailclient.engine.send_wecom") as wecom, \
             patch("mailclient.engine.send_smtp") as smtp:
            self.engine.poll_once(self.state)
        wecom.assert_called_once()
        smtp.assert_called_once()
        self.assertEqual(self.state.records()["new"], (True, True, False))
        self.assertIsNone(self.state.load_connectivity()["success_sent_at"])

    def test_mailbox_only_diagnostic_never_observes_or_sends_health_notifications(self):
        pop = MagicMock()
        pop.stat.return_value = (0, 0)
        pop.uidl.return_value = (b"+OK", [], 0)
        observer = Mock()
        with patch("mailclient.transports.socket.getaddrinfo"), \
             patch("mailclient.transports.socket.create_connection"), \
             patch("mailclient.transports._ClosingPOP3SSL", return_value=pop), \
             patch("mailclient.transports.send_wecom") as sender:
            result = diagnose(self.cfg, mailbox_only=True, connectivity=observer)
        self.assertTrue(result.mailbox_ok)
        observer.success.assert_not_called()
        observer.failure.assert_not_called()
        sender.assert_not_called()

    def test_failed_health_notification_does_not_block_an_independently_working_channel(self):
        pop = MagicMock()
        pop.stat.return_value = (0, 0)
        pop.uidl.return_value = (b"+OK", [], 0)
        self.monitor.sender = Mock(side_effect=OSError("health notification failed"))
        with patch("mailclient.transports.socket.getaddrinfo"), \
             patch("mailclient.transports.socket.create_connection"), \
             patch("mailclient.transports._ClosingPOP3SSL", return_value=pop), \
             patch("mailclient.transports.send_wecom") as test_sender:
            result = diagnose(self.cfg, stop_event=self.stop, connectivity=self.monitor)
        self.assertTrue(result.can_forward)
        self.assertTrue(result.channels["wecom"])
        test_sender.assert_called_once()
        self.assertIsNone(self.state.load_connectivity()["success_sent_at"])

    def test_health_payload_has_its_own_title_and_preserves_member_mentions(self):
        mail = Mail("邮箱连通成功", date="2026-11-14", plain="邮件列表读取成功。")
        for kind in ("text", "markdown"):
            cfg = replace(self.cfg, wecom_type=kind, wecom_userids="zhangsan")
            payload = wecom_payload(cfg, mail, notification=True)
            content = payload[kind]["content"]
            self.assertIn("邮箱连通成功", content)
            self.assertNotIn("新邮件", content)
            if kind == "text":
                self.assertEqual(payload[kind]["mentioned_list"], ["zhangsan"])
            else:
                self.assertTrue(content.startswith("<@zhangsan>"))

    def test_loopback_diagnostic_and_polling_share_health_state_and_third_failure_alert(self):
        # Real socket deadlines and the actual shared 3.2s limiter use real time.
        self.monotonic.stop()
        with server_instance(ThreadedTCP, PopHandler) as pop, \
             server_instance(ThreadingHTTPServer, WebhookHandler) as webhook:
            cfg = replace(self.cfg, pop_host="127.0.0.1", pop_port=pop.server_address[1],
                          pop_security="不加密", timeout_seconds=3,
                          wecom_webhook=f"http://127.0.0.1:{webhook.server_address[1]}/test")
            state = StateStore(self.folder / "loopback.sqlite3", cfg.account_id)
            try:
                monitor = ConnectivityMonitor(cfg, state, self.stop, clock=lambda: self.now)
                result = diagnose(cfg, stop_event=self.stop, connectivity=monitor)
                self.assertTrue(result)
                self.assertEqual(len(webhook.payloads), 1)
                self.assertIn("邮箱连通成功", webhook.payloads[0]["markdown"]["content"])
                engine = Forwarder(cfg, self.folder, self.stop, connectivity=monitor)
                engine.poll_once(state)
                self.assertEqual(len(webhook.payloads), 1)
                pop.user_reply = b"-ERR [AUTH] POP3 disabled"
                for index in range(3):
                    with self.assertRaises(TransportError):
                        engine.poll_once(state)
                    self.assertEqual(len(webhook.payloads), 2 if index == 2 else 1)
                content = webhook.payloads[-1]["markdown"]["content"]
                self.assertIn("邮箱连接异常", content)
                self.assertIn("连续 3 次", content)
                self.assertIn("POP3 disabled", content)
                with self.assertRaises(TransportError):
                    engine.poll_once(state)
                self.assertEqual(len(webhook.payloads), 2)
                pop.user_reply = b"+OK accepted"
                engine.poll_once(state)
                self.assertEqual(state.load_connectivity()["failures"], 0)
                self.assertEqual(len(webhook.payloads), 2)
                self.assertNotIn("DELE", pop.commands)
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()
