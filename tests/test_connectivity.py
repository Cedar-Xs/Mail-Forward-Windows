from dataclasses import replace
import threading
import unittest
from unittest.mock import Mock, patch

from mailclient.cancellation import Cancelled
from mailclient.config import Config
from mailclient.health import ConnectivityMonitor
from mailclient.parsing import Mail
from mailclient.transports import TransportError


class FakeState:
    def __init__(self):
        self.saved = {}

    def load_connectivity(self):
        return dict(self.saved)

    def save_connectivity(self, record):
        self.saved = dict(record)


class ConnectivityTests(unittest.TestCase):
    def setUp(self):
        self.cfg = replace(Config(), pop_host="pop.example.test", pop_user="person@example.test",
                           pop_password="fake-private-password", wecom_webhook="https://example.test/?key=FAKE-KEY",
                           smtp_user="sender@example.test", smtp_host="smtp.example.test", smtp_password="fake-smtp-secret")
        self.state = FakeState()
        self.stop = threading.Event()
        self.now = 1_000_000.0
        self.sent = []
        self.emit = Mock()
        self.patcher = patch("mailclient.health.time.monotonic", side_effect=lambda: self.now)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.monitor = self.make_monitor()
        self.error = TransportError("login", "POP3 rejected")

    def make_monitor(self, **kwargs):
        sender = kwargs.pop("sender", lambda cfg, mail, **kw: self.sent.append(mail))
        return ConnectivityMonitor(self.cfg, self.state, self.stop, self.emit,
                                   clock=lambda: self.now, sender=sender, **kwargs)

    def tick(self, seconds=3.2):
        self.now += seconds

    def fail_three(self, monitor=None):
        monitor = monitor or self.monitor
        self.assertIsNone(monitor.failure(self.error))
        self.assertIsNone(monitor.failure(self.error))
        return monitor.failure(self.error)

    def test_third_consecutive_failure_sends_and_success_clears_count(self):
        self.assertTrue(self.fail_three())
        self.assertEqual(self.sent[-1].subject, "邮箱连接异常")
        self.assertEqual(self.state.saved["failures"], 3)
        self.tick()
        self.assertTrue(self.monitor.success(7))
        self.assertEqual(self.state.saved["failures"], 0)
        self.assertIn("7 封", self.sent[-1].plain)
        self.assertIsNone(self.monitor.failure(self.error))
        self.assertEqual(self.state.saved["failures"], 1)

    def test_failure_cooldown_persists_and_exact_boundary_allows_send(self):
        self.assertTrue(self.fail_three())
        self.tick(12 * 3600 - 0.01)
        restarted = self.make_monitor()
        self.assertIsNone(restarted.failure(self.error))
        self.tick(0.01)
        self.assertTrue(restarted.failure(self.error))
        self.assertEqual(len(self.sent), 2)

    def test_failure_streak_survives_monitor_rebuild(self):
        self.monitor.failure(self.error)
        self.monitor.failure(self.error)
        restarted = self.make_monitor()
        self.assertTrue(restarted.failure(self.error))
        self.assertEqual(restarted.record["failures"], 3)

    def test_success_and_failure_cooldowns_are_independent(self):
        self.assertTrue(self.monitor.success(0))
        self.tick()
        self.assertTrue(self.fail_three())
        self.tick()
        self.assertIsNone(self.monitor.success(2))
        self.assertEqual(self.state.saved["failures"], 0)
        self.assertEqual([mail.subject for mail in self.sent], ["邮箱连通成功", "邮箱连接异常"])

    def test_stable_success_does_not_send_periodically_after_twelve_hours(self):
        self.assertTrue(self.monitor.success(0))
        self.tick(13 * 3600)
        self.assertIsNone(self.monitor.success(0))
        self.assertEqual(len(self.sent), 1)

    def test_success_suppressed_on_restart_stays_suppressed_until_new_failure(self):
        self.assertTrue(self.monitor.success(0))
        self.tick(10)
        restarted = self.make_monitor()
        self.assertIsNone(restarted.success(1))
        self.tick(13 * 3600)
        self.assertIsNone(restarted.success(2))
        self.assertIsNone(restarted.failure(self.error))
        self.assertTrue(restarted.success(3))
        self.assertEqual(len(self.sent), 2)

    def test_success_exact_boundary_on_new_session_sends(self):
        self.assertTrue(self.monitor.success(0))
        self.tick(12 * 3600)
        self.assertTrue(self.make_monitor().success(1))

    def test_failed_success_send_retries_after_sixty_seconds_without_spending_cooldown(self):
        sender = Mock(side_effect=[RuntimeError("offline"), None])
        monitor = self.make_monitor(sender=sender)
        self.assertFalse(monitor.success(1))
        self.assertIsNone(self.state.saved["success_sent_at"])
        self.tick(59)
        restarted = self.make_monitor(sender=sender)
        self.assertIsNone(restarted.success(1))
        self.tick(1)
        self.assertTrue(restarted.success(1))
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(self.state.saved["success_sent_at"], self.now)

    def test_failed_failure_send_retries_after_sixty_seconds(self):
        sender = Mock(side_effect=[RuntimeError("offline"), None])
        monitor = self.make_monitor(sender=sender)
        self.assertFalse(self.fail_three(monitor))
        self.assertIsNone(self.state.saved["failure_sent_at"])
        self.tick(59)
        self.assertIsNone(monitor.failure(self.error))
        self.tick(1)
        self.assertTrue(monitor.failure(self.error))
        self.assertEqual(sender.call_count, 2)

    def test_cancelled_is_not_counted_or_swallowed(self):
        with self.assertRaises(Cancelled):
            self.monitor.failure(Cancelled())
        self.assertEqual(self.monitor.record["failures"], 0)
        monitor = self.make_monitor(sender=Mock(side_effect=Cancelled()))
        with self.assertRaises(Cancelled):
            monitor.success(1)
        self.assertIsNone(monitor.record["success_sent_at"])
        self.stop.set()
        with self.assertRaises(Cancelled):
            self.monitor.success(0)
        self.assertFalse(self.sent)

    def test_disabled_or_missing_webhook_never_sends(self):
        original = self.cfg
        for change in ({"wecom_enabled": False}, {"wecom_webhook": ""}):
            with self.subTest(change=change):
                self.cfg = replace(original, **change)
                monitor = self.make_monitor()
                self.assertIsNone(monitor.success(0))
                self.assertIsNone(self.fail_three(monitor))
        self.assertFalse(self.sent)

    def test_persistence_errors_warn_and_in_memory_cooldown_survives(self):
        self.state.save_connectivity = Mock(side_effect=OSError("disk full"))
        self.assertTrue(self.monitor.success(1))
        self.assertIsNone(self.monitor.success(1))
        self.tick()
        self.assertTrue(self.fail_three())
        self.tick(60)
        self.assertIsNone(self.monitor.failure(self.error))
        self.assertEqual(len(self.sent), 2)
        self.assertTrue(any(call.kwargs.get("level") == "WARNING" for call in self.emit.call_args_list))

    def test_loading_state_error_does_not_block_notification(self):
        self.state.load_connectivity = Mock(side_effect=OSError("unreadable"))
        monitor = self.make_monitor()
        self.assertTrue(monitor.success(0))
        self.assertTrue(any(call.kwargs.get("level") == "WARNING" for call in self.emit.call_args_list))

    def test_failure_reason_hides_credentials_accounts_and_private_hosts(self):
        error = TransportError("login", "\r\n".join((self.cfg.pop_password, self.cfg.wecom_webhook,
                              self.cfg.smtp_password, self.cfg.pop_user.upper(), self.cfg.pop_host.upper(),
                              self.cfg.smtp_user, self.cfg.smtp_host)) + "\n" + "a" * 1000)
        self.monitor.failure(error)
        self.monitor.failure(error)
        self.assertTrue(self.monitor.failure(error))
        mail = self.sent[-1]
        for value in (self.cfg.pop_password, self.cfg.wecom_webhook, self.cfg.smtp_password,
                      self.cfg.pop_user, self.cfg.pop_host, self.cfg.smtp_user, self.cfg.smtp_host):
            self.assertNotIn(value.lower(), mail.plain.lower())
        self.assertLess(len(mail.plain), 400)
        self.assertEqual(mail.attachments, [])
        self.assertEqual(mail.html, "")
        self.assertIsNone(mail.code)

    def test_shared_delivery_waits_after_health_and_records_failed_attempts(self):
        self.assertTrue(self.monitor.success(0))
        self.now += 1
        self.stop.wait = Mock(return_value=False)
        normal_sender = Mock(side_effect=RuntimeError("rejected"))
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            self.monitor.deliver(Mail(subject="ordinary"), sender=normal_sender)
        self.stop.wait.assert_called_once()
        self.assertAlmostEqual(self.stop.wait.call_args.args[0], 2.2)
        self.assertEqual(self.monitor.last_wecom, self.now)

    def test_health_waits_after_normal_delivery_and_cancel_can_interrupt_wait(self):
        normal_sender = Mock()
        self.monitor.deliver(Mail(subject="ordinary"), sender=normal_sender)
        self.now += 1
        self.stop.wait = Mock(return_value=True)
        with self.assertRaises(Cancelled):
            self.monitor.success(0)
        self.assertAlmostEqual(self.stop.wait.call_args.args[0], 2.2)
        self.assertFalse(self.sent)
        self.assertIsNone(self.monitor.record["success_sent_at"])

    def test_health_send_error_is_warning_only_and_redacted(self):
        sender = Mock(side_effect=RuntimeError(self.cfg.pop_user + " " + self.cfg.pop_password))
        monitor = self.make_monitor(sender=sender)
        self.assertFalse(monitor.success(0))
        warnings = [call.kwargs["text"] for call in self.emit.call_args_list
                    if call.kwargs.get("level") == "WARNING"]
        self.assertTrue(warnings)
        for text in warnings:
            self.assertNotIn(self.cfg.pop_user, text)
            self.assertNotIn(self.cfg.pop_password, text)

    def test_default_sender_marks_health_notification(self):
        monitor = ConnectivityMonitor(self.cfg, self.state, self.stop, clock=lambda: self.now)
        with patch("mailclient.health.send_wecom") as sender:
            self.assertTrue(monitor.success(0))
        self.assertTrue(sender.call_args.kwargs["notification"])


if __name__ == "__main__":
    unittest.main()
