"""Mailbox health notifications with durable, independent delivery cooldowns."""
from __future__ import annotations

from datetime import datetime
import math
import re
import time

from .cancellation import Cancelled, check_cancel
from .parsing import Mail
from .transports import safe_error, send_wecom, silent_emit


class ConnectivityMonitor:
    COOLDOWN_SECONDS = 12 * 60 * 60
    RETRY_SECONDS = 60
    FAILURE_THRESHOLD = 3
    WECOM_INTERVAL_SECONDS = 3.2

    def __init__(self, cfg, state, stop_event, emit=silent_emit, clock=None, sender=None):
        self.cfg, self.state, self.stop_event, self.emit = cfg, state, stop_event, emit
        self.clock = clock if clock is not None else time.time
        self.sender = sender
        self.last_wecom = 0.0
        self.success_pending = True
        self._notice_keys = {}
        self.record = {"failures": 0, "failure_sent_at": None, "success_sent_at": None,
                       "failure_attempt_at": None, "success_attempt_at": None}
        try:
            saved = state.load_connectivity()
            self.record["failures"] = max(0, int(saved.get("failures", 0)))
            for key in self.record.keys() - {"failures"}:
                value = saved.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
                    self.record[key] = value
        except Cancelled:
            raise
        except Exception as exc:
            self._warning("连通提醒状态读取失败，本次使用内存状态", exc)

    def _reason(self, exc):
        text = safe_error(exc, self.cfg)
        identities = (self.cfg.pop_user, self.cfg.pop_host, self.cfg.smtp_user, self.cfg.smtp_host)
        for value in sorted((value for value in identities if value), key=len, reverse=True):
            text = re.sub(re.escape(value), "[已隐藏]", text, flags=re.IGNORECASE)
        return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:300]

    def _warning(self, message, exc):
        self.emit("log", level="WARNING", text=message + "：" + self._reason(exc))

    def _notice(self, key, text):
        category = key[:2] if isinstance(key, tuple) else key
        if self._notice_keys.get(category) != key:
            self._notice_keys[category] = key
            self.emit("log", level="INFO", text=text)

    def _save(self):
        try:
            self.state.save_connectivity(dict(self.record))
        except Cancelled:
            raise
        except Exception as exc:
            # Keep the in-process state: a broken disk must not create a flood
            # or stop ordinary mail delivery. A restart cannot recover this save.
            self._warning("连通提醒状态保存失败，本进程继续限频", exc)

    def deliver(self, mail, sender=None):
        """Share rate limiting with ordinary mail; let its caller handle errors."""
        check_cancel(self.stop_event)
        delay = max(0.0, self.WECOM_INTERVAL_SECONDS - (time.monotonic() - self.last_wecom))
        if delay:
            if self.stop_event is None:
                time.sleep(delay)
            elif self.stop_event.wait(delay):
                raise Cancelled()
        check_cancel(self.stop_event)
        # Record attempts too: failed requests still count toward webhook limits.
        self.last_wecom = time.monotonic()
        if sender is not None:
            return sender(self.cfg, mail, stop_event=self.stop_event)
        if self.sender is not None:
            return self.sender(self.cfg, mail, stop_event=self.stop_event)
        return send_wecom(self.cfg, mail, stop_event=self.stop_event, notification=True)

    def _notify(self, kind, mail):
        if not self.cfg.wecom_enabled or not self.cfg.wecom_webhook:
            self._notice("disabled", "邮箱状态通知未发送：企业微信通道未启用或未配置 Webhook。")
            return None
        now = self.clock()
        sent_at = self.record[kind + "_sent_at"]
        if sent_at is not None and now - sent_at < self.COOLDOWN_SECONDS:
            try:
                eligible = datetime.fromtimestamp(sent_at + self.COOLDOWN_SECONDS).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
            except (OverflowError, OSError, ValueError):
                # A damaged timestamp must not make an optional log message
                # interrupt mailbox processing or bypass the existing cooldown.
                next_allowed = ""
            else:
                next_allowed = f"，下次允许时间 {eligible}"
            self._notice((kind, "cooldown", sent_at), f"{mail.subject}通知未发送：12 小时限频中{next_allowed}。")
            if kind == "success":
                self.success_pending = False
            return None
        attempted_at = self.record[kind + "_attempt_at"]
        if attempted_at is not None and now - attempted_at < self.RETRY_SECONDS:
            self._notice((kind, "retry", attempted_at), f"{mail.subject}通知等待重试：上次尝试未满 60 秒。")
            return None
        self.record[kind + "_attempt_at"] = now
        self._save()
        try:
            self.deliver(mail)
        except Cancelled:
            raise
        except Exception as exc:
            self._warning("连通提醒发送失败，将按重试间隔重试", exc)
            self.emit("status", key="wecom", level="error", text="邮箱状态通知发送失败 · 等待重试")
            return False
        self.record[kind + "_sent_at"] = self.clock()
        if kind == "success":
            self.success_pending = False
        self._save()
        self.emit("status", key="wecom", level="ok", text="企业微信已接受" + mail.subject + "通知")
        self.emit("log", level="INFO", text=mail.subject + "提醒已被企业微信接口接受。")
        return True

    def success(self, count: int):
        check_cancel(self.stop_event)
        if self.record["failures"]:
            self.emit("log", level="INFO", text="邮箱检查已恢复成功，连续失败计数已清零。")
            self.record["failures"] = 0
            self._save()
        if not self.success_pending:
            return None
        mail = Mail(subject="邮箱连通成功", sender="邮件转发助手",
                    date=datetime.fromtimestamp(self.clock()).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
                    plain=f"检查状态：邮箱连接、账号登录及邮件列表读取成功。\n邮件数量：{count} 封。")
        return self._notify("success", mail)

    def failure(self, exc):
        check_cancel(self.stop_event)
        if isinstance(exc, Cancelled):
            raise exc
        self.record["failures"] += 1
        self.success_pending = True
        self._save()
        if self.record["failures"] < self.FAILURE_THRESHOLD:
            self.emit("log", level="INFO", text=f"邮箱检查连续失败 {self.record['failures']}/{self.FAILURE_THRESHOLD} 次，达到阈值后尝试企业微信告警。")
            return None
        stage = {"network": "邮箱网络", "login": "账号登录", "mailbox": "邮件列表读取"}.get(
            getattr(exc, "stage", None), "邮箱检查")
        mail = Mail(subject="邮箱连接异常", sender="邮件转发助手",
                    date=datetime.fromtimestamp(self.clock()).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
                    plain=f"检查状态：连续 {self.record['failures']} 次邮箱检查失败。\n"
                          f"失败阶段：{stage}。\n原因：{self._reason(exc)}")
        return self._notify("failure", mail)
