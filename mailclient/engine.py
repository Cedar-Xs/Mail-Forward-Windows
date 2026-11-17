"""Cancellable polling; checkpoint each successful channel independently."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3
import threading

from .config import Config, split_list
from .cancellation import check_cancel
from .parsing import is_excluded_sender, matches_keywords, parse_mail
from .state import StateStore
from .health import ConnectivityMonitor
from .transports import (Cancelled, TransportError, pop_session, safe_error, send_smtp,
                         send_wecom, silent_emit, uidl_list)


class Forwarder:
    def __init__(self, cfg: Config, folder: Path, stop: threading.Event, emit=silent_emit,
                 connectivity=None):
        self.cfg, self.folder, self.stop, self.emit = cfg, folder, stop, emit
        self.connectivity = connectivity
        self._last_wecom = 0.0

    @property
    def last_wecom(self):
        return self.connectivity.last_wecom if self.connectivity is not None else self._last_wecom

    @last_wecom.setter
    def last_wecom(self, value):
        self._last_wecom = value
        if self.connectivity is not None:
            self.connectivity.last_wecom = value

    def poll_once(self, state: StateStore) -> None:
        if self.stop.is_set():
            return
        if self.connectivity is None:
            self.connectivity = ConnectivityMonitor(self.cfg, state, self.stop, self.emit)
            self.connectivity.last_wecom = self._last_wecom
        self._mailbox_ready = False
        try:
            self._poll_mailbox(state)
        except (Cancelled, sqlite3.DatabaseError):
            raise
        except Exception as exc:
            check_cancel(self.stop)
            if not self._mailbox_ready:
                self.connectivity.failure(exc)
            raise

    def _poll_mailbox(self, state: StateStore) -> None:
        with pop_session(self.cfg, self.emit, self.stop) as connection:
            try:
                count, _ = connection.stat()
                check_cancel(self.stop)
                items = uidl_list(connection)
            except Exception as exc:
                check_cancel(self.stop)
                raise TransportError("mailbox", "邮件列表读取失败：" + safe_error(exc, self.cfg)) from None
            check_cancel(self.stop)
            self._mailbox_ready = True
            self.emit("status", key="mailbox", level="ok", text=f"{count} 封邮件 · UIDL 正常")
            if len(items) != count:
                self.emit("log", level="WARNING", text="服务器 STAT 与 UIDL 数量不一致，转发以 UIDL 列表为准。")
            self.emit("phase", text="正在转发 · 邮箱检查正常")
            self.connectivity.success(count)
            if not state.initialized:
                state.initialize([uid for _, uid in items], self.cfg.test_latest_first_run)
                self.emit("log", level="INFO", text=f"已建立 {len(items)} 封历史邮件的基线；"
                          + ("最后一封进入测试流程，仍按排除名单和关键词过滤。" if self.cfg.test_latest_first_run and items else "历史邮件不转发。"))
            known = state.records()
            excluded = self.cfg.excluded_sender_addresses
            for number, uid in items:
                if self.stop.is_set():
                    break
                record = known.get(uid)
                if record and (record[2] or (record[0] and record[1])):
                    continue
                state.ensure(uid)
                if record is None:
                    self.emit("counter", key="discovered", amount=1)
                try:
                    _, lines, _ = connection.retr(number)
                except Exception as exc:
                    check_cancel(self.stop)
                    raise TransportError("mailbox", "邮件读取失败：" + safe_error(exc, self.cfg)) from exc
                check_cancel(self.stop)
                try:
                    mail = parse_mail(b"\r\n".join(lines))
                except Exception as exc:
                    self.emit("log", level="ERROR", text=f"邮件解析失败，后续邮件继续处理：{safe_error(exc, self.cfg)}")
                    self.emit("counter", key="failed", amount=1)
                    continue
                check_cancel(self.stop)
                # Sender exclusions also cancel any pending route on a partial delivery.
                if is_excluded_sender(mail, excluded):
                    state.ignore(uid)
                    self.emit("counter", key="filtered", amount=1)
                    self.emit("log", level="INFO", text="已跳过排除发件人的邮件，两个通道均不再投递。")
                    continue
                # Keyword changes alone do not cancel a partially delivered message.
                already_delivered = bool(record and (record[0] or record[1]))
                if not already_delivered and not matches_keywords(mail, split_list(self.cfg.keywords)):
                    state.ignore(uid)
                    self.emit("counter", key="filtered", amount=1)
                    continue
                # Record disabled channels only after parsing and filtering succeeded.
                for channel, enabled in (("wecom", self.cfg.wecom_enabled), ("smtp", self.cfg.smtp_enabled)):
                    if not enabled:
                        state.done(uid, channel)
                for channel, enabled, sender, index in (("wecom", self.cfg.wecom_enabled, send_wecom, 0),
                                                        ("smtp", self.cfg.smtp_enabled, send_smtp, 1)):
                    if self.stop.is_set():
                        break
                    if not enabled or (record and record[index]):
                        continue
                    try:
                        if channel == "wecom":
                            self.connectivity.deliver(mail, sender=sender)
                        else:
                            sender(self.cfg, mail, stop_event=self.stop)
                    except Cancelled:
                        raise
                    except Exception as exc:
                        check_cancel(self.stop)
                        text = safe_error(exc, self.cfg)
                        self.emit("status", key=channel, level="error", text="投递失败，下轮重试")
                        self.emit("counter", key="failed", amount=1)
                        self.emit("log", level="ERROR", text=f"{'企业微信' if channel == 'wecom' else 'SMTP'}投递失败：{text}")
                        continue
                    # Commit failure is fatal for the cycle: do not keep sending without checkpoints.
                    state.done(uid, channel)
                    self.emit("status", key=channel, level="ok", text="接口已接受消息" if channel == "wecom" else "SMTP 已接受邮件")
                    self.emit("counter", key="delivered", amount=1)
                    self.emit("log", level="INFO", text=f"{'企业微信' if channel == 'wecom' else 'SMTP'}投递成功，状态已保存。")

    def run(self) -> None:
        state = StateStore(self.folder / "delivery.sqlite3", self.cfg.account_id)
        try:
            self.emit("log", level="INFO", text="转发已启动；原邮箱邮件不会被本客户端删除。")
            while not self.stop.is_set():
                try:
                    self.poll_once(state)
                except sqlite3.DatabaseError:
                    # Stop on failed checkpoints, rather than risk repeatedly sending without records.
                    raise
                except Cancelled:
                    break
                except Exception as exc:
                    if self.stop.is_set():
                        break
                    key = exc.stage if isinstance(exc, TransportError) else "mailbox"
                    self.emit("status", key=key, level="error", text=safe_error(exc, self.cfg))
                    if key == "network":
                        self.emit("status", key="login", level="idle", text="等待重新连接")
                        self.emit("status", key="mailbox", level="idle", text="等待重新连接")
                    elif key == "login":
                        self.emit("status", key="mailbox", level="idle", text="等待重新登录")
                    self.emit("counter", key="failed", amount=1)
                    self.emit("log", level="ERROR", text="本轮检查失败，将自动重试：" + safe_error(exc, self.cfg))
                    self.emit("phase", text="正在监测 · 邮箱检查失败，等待重试")
                finally:
                    self.emit("checked", time=datetime.now().strftime("%H:%M:%S"))
                if self.stop.wait(self.cfg.poll_seconds):
                    break
        finally:
            state.close()
            self.emit("log", level="INFO", text="转发已停止。")
