"""Real start-button, POP3 and webhook regressions for continuous monitoring.

These desktop checks run in Windows CI. All network traffic stays on loopback;
no diagnostic, forwarder or health sender is replaced by a mock.
"""
from dataclasses import replace
from email.message import EmailMessage
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import customtkinter as ctk

from mailclient.config import Config
from mailclient.gui import ClientWindow
from mailclient.health import ConnectivityMonitor
import test_protocols as protocol


class RecoveringPopServer(protocol.ThreadedTCP):
    """The first USER commands are really rejected over the POP3 socket."""

    def __init__(self, *args, **kwargs):
        self.user_attempts = 0
        self.initial_rejections = 0
        self.disconnect_on_connect = False
        self.disconnect_attempts = 0
        self.third_disconnect_entered = threading.Event()
        self.allow_third_disconnect = threading.Event()
        self.allow_recovery = threading.Event()
        self.observation_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    @property
    def user_reply(self):
        with self.observation_lock:
            self.user_attempts += 1
            reject = self.user_attempts <= self.initial_rejections
        return b"-ERR [AUTH] temporary login failure" if reject else b"+OK user accepted"


class DisconnectingPopHandler(protocol.PopHandler):
    """Drop real POP3 connections; gate the third drop for an exact threshold check."""

    def exchange(self):
        with self.server.observation_lock:
            disconnect = self.server.disconnect_on_connect
            if disconnect:
                self.server.disconnect_attempts += 1
                attempt = self.server.disconnect_attempts
        if not disconnect:
            return super().exchange()
        if attempt == 3:
            self.server.third_disconnect_entered.set()
            if not self.server.allow_third_disconnect.wait(5):
                return
        elif attempt > 3:
            # Keep a later connection pending until the test restores service;
            # this prevents an accidental fourth failure racing its assertions.
            if not self.server.allow_recovery.wait(5):
                return
            with self.server.observation_lock:
                disconnect = self.server.disconnect_on_connect
            if not disconnect:
                return super().exchange()
        # No POP3 greeting is sent: returning closes the actual accepted socket.


class RecordingWebhook(protocol.WebhookHandler):
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8"))
        content = payload[payload["msgtype"]]["content"]
        with self.server.observation_lock:
            error = self.server.business_error
            self.server.payloads.append(payload)
            if not error:
                self.server.accepted.append(payload)
            if "邮箱连接异常" in content:
                with self.server.pop.observation_lock:
                    self.server.failure_at_user_attempts.append(self.server.pop.user_attempts)
        result = json.dumps({"errcode": error, "errmsg": "simulated unavailable" if error else "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)
        self.wfile.flush()
        # Wake the test only after the actual HTTP response has been written.
        if "邮箱连接异常" in content and not error:
            self.server.failure_accepted.set()
        if "邮箱连通成功" in content:
            self.server.success_attempted.set()
            if not error:
                self.server.success_accepted.set()


class ObservedWindow(ClientWindow):
    """Observe real queued worker events without changing their processing."""

    def __init__(self, *args, **kwargs):
        self.observed = []
        self.observation_changed = threading.Condition()
        super().__init__(*args, **kwargs)

    def post(self, kind, **data):
        super().post(kind, **data)
        with self.observation_changed:
            self.observed.append({"kind": kind, **data})
            self.observation_changed.notify_all()

    def event_count(self, kind):
        with self.observation_changed:
            return sum(event["kind"] == kind for event in self.observed)

    def wait_for(self, predicate, timeout=6):
        with self.observation_changed:
            return self.observation_changed.wait_for(lambda: predicate(self.observed), timeout)


class VirtualWallClock:
    def __init__(self):
        self.value = time.time()
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.value

    def advance(self, seconds):
        with self.lock:
            self.value += seconds


@unittest.skipUnless(sys.platform == "win32" or os.environ.get("DISPLAY"),
                     "A native Windows desktop or X display is required")
class MonitoringStartFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = ctk.CTk()
        self.root.withdraw()
        self.window = ObservedWindow(self.root, Path(self.tmp.name))
        self.root.update()

    def tearDown(self):
        self.window.stop_event.set()
        if self.window.worker:
            self.window.worker.join(timeout=4)
        for timer in self.root.tk.call("after", "info"):
            self.root.after_cancel(timer)
        self.window.shutdown()
        self.root.destroy()
        self.tmp.cleanup()

    @staticmethod
    def configure_webhook(webhook, pop, business_error=0):
        webhook.pop = pop
        webhook.business_error = business_error
        webhook.accepted = []
        webhook.failure_at_user_attempts = []
        webhook.observation_lock = threading.Lock()
        webhook.failure_accepted = threading.Event()
        webhook.success_attempted = threading.Event()
        webhook.success_accepted = threading.Event()

    def configure_window(self, pop, webhook):
        values = {
            "pop_host": "127.0.0.1", "pop_port": pop.server_address[1], "pop_security": "不加密",
            "pop_user": "user@example.test", "pop_password": "fake-password", "timeout_seconds": 3,
            "wecom_enabled": True, "wecom_webhook": f"http://127.0.0.1:{webhook.server_address[1]}/test",
            "smtp_enabled": False, "keywords": "", "test_latest_first_run": False,
            "remember_credentials": False, "poll_seconds": 3,
        }
        for key, value in values.items():
            self.window.vars[key].set(value)

    @staticmethod
    def loopback_validation(cfg, require_channels=True):
        # Keep ordinary validation; only the in-process HTTP fixture and shorter
        # polling are test exceptions. Production accepts HTTPS webhooks only.
        validated = replace(cfg, wecom_webhook="https://example.test/send?key=FAKE-KEY")
        ORIGINAL_VALIDATE(validated, require_channels=require_channels)
        cfg.poll_seconds = 0.05

    def wait_for_checks(self, count):
        self.assertTrue(self.window.wait_for(lambda events: sum(e["kind"] == "checked" for e in events) >= count),
                        self.failure_details())

    def wait_for_empty_baseline(self):
        self.assertTrue(self.window.wait_for(lambda events: any(
            e["kind"] == "log" and e.get("text", "").startswith("已建立 0 封历史邮件的基线")
            for e in events)), self.failure_details())

    def wait_for_deliveries(self, count):
        self.assertTrue(self.window.wait_for(lambda events: sum(
            e.get("amount", 0) for e in events if e["kind"] == "counter" and e.get("key") == "delivered"
        ) >= count), self.failure_details())

    @staticmethod
    def publish_mail(pop, uid, subject):
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = "sender@example.test"
        message.set_content("This new mail must be forwarded exactly once.")
        pop.messages.append((uid, message.as_bytes()))

    def failure_details(self):
        with self.window.observation_changed:
            return "\n".join(event.get("text", event["kind"]) for event in self.window.observed[-20:])

    @staticmethod
    def matching_payloads(webhook, fragment, *, accepted=True):
        with webhook.observation_lock:
            payloads = webhook.accepted if accepted else webhook.payloads
            return [payload for payload in payloads if fragment in payload[payload["msgtype"]]["content"]]

    def stop_and_finish(self):
        self.window.stop()
        self.window.worker.join(timeout=4)
        self.assertFalse(self.window.worker.is_alive(), self.failure_details())
        self.window._finish_when_stopped()
        self.root.update()
        self.assertEqual(str(self.window.start_button.cget("state")), "normal")

    def test_start_retries_initial_login_failures_notifies_recovers_and_forwards_new_mail_once(self):
        with protocol.server_instance(RecoveringPopServer, protocol.PopHandler) as pop, \
             protocol.server_instance(ThreadingHTTPServer, RecordingWebhook) as webhook:
            pop.initial_rejections = 3
            self.configure_webhook(webhook, pop)
            self.configure_window(pop, webhook)
            with patch.object(Config, "validate", self.loopback_validation), \
                 patch.object(ConnectivityMonitor, "WECOM_INTERVAL_SECONDS", 0.01):
                self.window.launch("start")
                self.assertTrue(webhook.failure_accepted.wait(6), self.failure_details())
                failure = self.matching_payloads(webhook, "邮箱连接异常")
                self.assertEqual(len(failure), 1)
                self.assertIn("连续 3 次", failure[0][failure[0]["msgtype"]]["content"])
                self.assertEqual(webhook.failure_at_user_attempts, [3])
                self.assertTrue(webhook.success_accepted.wait(6), self.failure_details())
                # Failed polls also emit checked. Wait for the explicit baseline
                # commit instead, before publishing a genuinely new mail.
                self.wait_for_empty_baseline()
                message = EmailMessage()
                message["Subject"] = "monitoring-flow-new-mail"
                message["From"] = "sender@example.test"
                message.set_content("This new mail must be forwarded exactly once.")
                pop.messages.append(("monitoring-new-uid", message.as_bytes()))
                self.assertTrue(self.window.wait_for(lambda events: any(
                    e["kind"] == "counter" and e.get("key") == "delivered" for e in events)),
                    self.failure_details())
                self.wait_for_checks(self.window.event_count("checked") + 2)
                self.stop_and_finish()
            self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功")), 1)
            self.assertEqual(len(self.matching_payloads(webhook, "monitoring-flow-new-mail")), 1)
            self.assertNotIn("DELE", pop.commands)

    def test_running_forwarder_reports_third_disconnect_and_recovers_with_independent_cooldowns(self):
        clock = VirtualWallClock()
        health_time = SimpleNamespace(time=clock, monotonic=time.monotonic, sleep=time.sleep)
        with protocol.server_instance(RecoveringPopServer, DisconnectingPopHandler) as pop, \
             protocol.server_instance(ThreadingHTTPServer, RecordingWebhook) as webhook:
            self.configure_webhook(webhook, pop)
            self.configure_window(pop, webhook)
            with patch.object(Config, "validate", self.loopback_validation), \
                 patch.object(ConnectivityMonitor, "WECOM_INTERVAL_SECONDS", 0.01), \
                 patch("mailclient.health.time", health_time):
                self.window.launch("start")
                self.assertTrue(webhook.success_accepted.wait(6), self.failure_details())
                self.wait_for_empty_baseline()
                self.publish_mail(pop, "before-outage-uid", "mail-before-network-outage")
                self.wait_for_deliveries(1)
                self.wait_for_checks(self.window.event_count("checked") + 1)

                with pop.observation_lock:
                    pop.disconnect_on_connect = True
                # The third socket is accepted but its close is gated. The first
                # two real failures have completed, so no alert may exist yet.
                self.assertTrue(pop.third_disconnect_entered.wait(6), self.failure_details())
                self.assertFalse(webhook.failure_accepted.is_set())
                self.assertEqual(self.matching_payloads(webhook, "邮箱连接异常"), [])
                with self.window.observation_changed:
                    failed = sum(e.get("amount", 0) for e in self.window.observed
                                 if e["kind"] == "counter" and e.get("key") == "failed")
                self.assertEqual(failed, 2)
                pop.allow_third_disconnect.set()
                self.assertTrue(webhook.failure_accepted.wait(6), self.failure_details())
                failures = self.matching_payloads(webhook, "邮箱连接异常")
                self.assertEqual(len(failures), 1)
                content = failures[0][failures[0]["msgtype"]]["content"]
                self.assertIn("连续 3 次", content)
                self.assertIn("失败阶段：邮箱网络", content)

                with pop.observation_lock:
                    pop.disconnect_on_connect = False
                pop.allow_recovery.set()
                self.assertTrue(self.window.wait_for(lambda events: any(
                    e["kind"] == "log" and "邮箱连通成功通知未发送：12 小时限频中" in e.get("text", "")
                    for e in events)), self.failure_details())
                self.publish_mail(pop, "after-outage-uid", "mail-after-network-outage")
                self.wait_for_deliveries(2)
                self.wait_for_checks(self.window.event_count("checked") + 2)
                self.stop_and_finish()

            # A success notification was already sent before the outage. Its
            # 12-hour cooldown suppresses recovery success, independently of the
            # failure alert; normal mail still flows on both sides of the outage.
            self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功")), 1)
            self.assertEqual(len(self.matching_payloads(webhook, "邮箱连接异常")), 1)
            self.assertEqual(len(self.matching_payloads(webhook, "mail-before-network-outage")), 1)
            self.assertEqual(len(self.matching_payloads(webhook, "mail-after-network-outage")), 1)
            self.assertNotIn("DELE", pop.commands)

    def test_initial_webhook_failure_retries_success_notification_without_new_mail(self):
        clock = VirtualWallClock()
        health_time = SimpleNamespace(time=clock, monotonic=time.monotonic, sleep=time.sleep)
        with protocol.server_instance(RecoveringPopServer, protocol.PopHandler) as pop, \
             protocol.server_instance(ThreadingHTTPServer, RecordingWebhook) as webhook:
            self.configure_webhook(webhook, pop, business_error=93000)
            self.configure_window(pop, webhook)
            with patch.object(Config, "validate", self.loopback_validation), \
                 patch.object(ConnectivityMonitor, "WECOM_INTERVAL_SECONDS", 0.01), \
                 patch("mailclient.health.time", health_time):
                self.window.launch("start")
                self.assertTrue(webhook.success_attempted.wait(6), self.failure_details())
                self.wait_for_checks(2)
                self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功", accepted=False)), 1)
                self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功")), 0)
                with webhook.observation_lock:
                    webhook.business_error = 0
                clock.advance(61)  # Preserve the real 60-second retry policy.
                self.assertTrue(webhook.success_accepted.wait(6), self.failure_details())
                self.wait_for_checks(self.window.event_count("checked") + 2)
                self.stop_and_finish()
            self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功", accepted=False)), 2)
            self.assertEqual(len(self.matching_payloads(webhook, "邮箱连通成功")), 1)
            self.assertEqual(pop.messages, [])
            self.assertNotIn("RETR", pop.commands)
            self.assertNotIn("DELE", pop.commands)


ORIGINAL_VALIDATE = Config.validate


if __name__ == "__main__":
    unittest.main()
