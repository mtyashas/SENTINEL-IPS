"""
response/alert_dispatcher.py

Purpose: Multi-channel alert dispatcher that sends threat notifications via
         Slack webhook, email (SMTP), and generic HTTP webhooks within 1 second
         of detection. Dispatches are fire-and-forget (background threads) so
         the detection pipeline is never blocked. Includes deduplication to
         prevent alert storms from high-frequency attacks.

Inputs:  Alert dict containing attack_type, severity, src_ip, detail, timestamp.
Outputs: Alerts sent to configured channels; AlertRecord logged for audit trail.

Usage:
    from response.alert_dispatcher import AlertDispatcher
    dispatcher = AlertDispatcher()
    dispatcher.dispatch({
        "attack_type": "DDoS",
        "severity":    "HIGH",
        "src_ip":      "1.2.3.4",
        "detail":      "1.2.3.4 rate-limited and blocked",
    })
"""

import json
import logging
import os
import smtplib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from queue import Empty, Queue
from typing import Optional

import requests

from config import LOG_DIR

logger = logging.getLogger(__name__)

_DEDUP_WINDOW_S   = 60     # suppress identical alerts within this window
_WORKER_TIMEOUT_S = 5      # per-channel send timeout
_QUEUE_MAX        = 1000   # max queued alerts before dropping

# ---------------------------------------------------------------------------
# Severity → minimum channel set (channels escalate upward)
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class AlertRecord:
    alert_id:    str
    timestamp:   datetime
    attack_type: str
    severity:    str
    src_ip:      str
    detail:      str
    channels_sent: list[str] = field(default_factory=list)
    deduplicated:  bool      = False


def _alert_id(alert: dict) -> str:
    """Stable fingerprint for deduplication: attack_type + src_ip + severity."""
    return f"{alert.get('attack_type','')}-{alert.get('src_ip','')}-{alert.get('severity','')}"


def _format_text(alert: dict) -> str:
    ts  = alert.get("timestamp", datetime.now(tz=timezone.utc))
    if isinstance(ts, datetime):
        ts = ts.isoformat()
    lines = [
        f"[SENTINEL IPS] {alert.get('severity','?')} ALERT",
        f"Attack : {alert.get('attack_type','Unknown')}",
        f"Source : {alert.get('src_ip','Unknown')}",
        f"Detail : {alert.get('detail','')}",
        f"MITRE  : {alert.get('mitre_technique_id','N/A')} — {alert.get('mitre_tactic','N/A')}",
        f"Time   : {ts}",
    ]
    return "\n".join(lines)


def _format_slack(alert: dict) -> dict:
    colour_map = {
        "CRITICAL": "#FF0000",
        "HIGH":     "#FF6600",
        "MEDIUM":   "#FFCC00",
        "LOW":      "#36A64F",
        "INFO":     "#439FE0",
    }
    severity = alert.get("severity", "INFO")
    return {
        "attachments": [{
            "color":  colour_map.get(severity, "#439FE0"),
            "title":  f"SENTINEL IPS — {severity} Alert",
            "fields": [
                {"title": "Attack",  "value": alert.get("attack_type", "?"), "short": True},
                {"title": "Source",  "value": alert.get("src_ip", "?"),      "short": True},
                {"title": "Detail",  "value": alert.get("detail", ""),       "short": False},
                {"title": "MITRE",
                 "value": f"{alert.get('mitre_technique_id','N/A')} — {alert.get('mitre_tactic','N/A')}",
                 "short": False},
            ],
            "footer": "CyberCore Intelligence | SENTINEL IPS v2.0",
            "ts":     int(time.time()),
        }]
    }


class AlertDispatcher:
    """
    Asynchronous multi-channel alert engine.

    Channels configured via environment variables:
      SLACK_WEBHOOK_URL    — Slack incoming webhook URL
      ALERT_EMAIL_TO       — recipient address (comma-separated for multiple)
      ALERT_EMAIL_FROM     — sender address
      ALERT_SMTP_HOST      — SMTP server hostname (default localhost)
      ALERT_SMTP_PORT      — SMTP port (default 25)
      ALERT_SMTP_USER      — SMTP username (optional)
      ALERT_SMTP_PASS      — SMTP password (optional)
      WEBHOOK_URL          — generic HTTP webhook endpoint
      ALERT_MIN_SEVERITY   — minimum severity to dispatch (default LOW)

    All channels are attempted in parallel background threads so the calling
    thread returns immediately and is never blocked by network I/O.

    Parameters:
        min_severity — override for minimum severity level to dispatch
    """

    def __init__(self, min_severity: str = "LOW") -> None:
        self._slack_url   = os.getenv("SLACK_WEBHOOK_URL", "")
        self._email_to    = [
            a.strip() for a in os.getenv("ALERT_EMAIL_TO", "").split(",")
            if a.strip()
        ]
        self._email_from  = os.getenv("ALERT_EMAIL_FROM", "sentinel@localhost")
        self._smtp_host   = os.getenv("ALERT_SMTP_HOST", "localhost")
        self._smtp_port   = int(os.getenv("ALERT_SMTP_PORT", "25"))
        self._smtp_user   = os.getenv("ALERT_SMTP_USER", "")
        self._smtp_pass   = os.getenv("ALERT_SMTP_PASS", "")
        self._webhook_url = os.getenv("WEBHOOK_URL", "")
        self._min_sev_idx = _SEVERITY_ORDER.index(min_severity) \
                            if min_severity in _SEVERITY_ORDER else 1

        self._dedup:    dict[str, float]  = {}
        self._records:  list[AlertRecord] = []
        self._lock      = threading.Lock()
        self._queue:    Queue             = Queue(maxsize=_QUEUE_MAX)
        self._audit_path = LOG_DIR / "alerts.jsonl"

        self._start_worker()

        channels_active = []
        if self._slack_url:
            channels_active.append("slack")
        if self._email_to:
            channels_active.append("email")
        if self._webhook_url:
            channels_active.append("webhook")
        if not channels_active:
            logger.warning(
                "AlertDispatcher: no channels configured — "
                "set SLACK_WEBHOOK_URL / ALERT_EMAIL_TO / WEBHOOK_URL"
            )
        else:
            logger.info("AlertDispatcher ready — channels: %s", channels_active)

    # ------------------------------------------------------------------
    # Worker thread
    # ------------------------------------------------------------------

    def _start_worker(self) -> None:
        t = threading.Thread(
            target=self._worker_loop, daemon=True, name="alert-worker"
        )
        t.start()

    def _worker_loop(self) -> None:
        while True:
            try:
                alert, record = self._queue.get(timeout=1)
                self._send_all(alert, record)
                self._queue.task_done()
            except Empty:
                continue
            except Exception as exc:
                logger.error("Alert worker error: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, alert: dict) -> Optional[AlertRecord]:
        """
        Queue an alert for async dispatch to all configured channels.

        Returns immediately. The alert is dispatched in a background thread
        within milliseconds. Returns None if the alert is deduplicated or
        below the minimum severity threshold.

        Inputs:  alert — dict with keys: attack_type, severity, src_ip, detail.
                         Optional: timestamp, mitre_technique_id, mitre_tactic
        Outputs: AlertRecord (queued for delivery) or None
        """
        severity = alert.get("severity", "INFO")
        sev_idx  = _SEVERITY_ORDER.index(severity) \
                   if severity in _SEVERITY_ORDER else 0

        if sev_idx < self._min_sev_idx:
            logger.debug("Alert below min severity (%s < %s) — suppressed",
                         severity, _SEVERITY_ORDER[self._min_sev_idx])
            return None

        aid = _alert_id(alert)
        now = time.monotonic()

        with self._lock:
            last = self._dedup.get(aid, 0.0)
            if now - last < _DEDUP_WINDOW_S:
                logger.debug("Alert deduplicated for %s (within %ds window)",
                             aid, _DEDUP_WINDOW_S)
                return None
            self._dedup[aid] = now

        record = AlertRecord(
            alert_id=f"ALT-{int(time.time() * 1000)}",
            timestamp=alert.get("timestamp", datetime.now(tz=timezone.utc)),
            attack_type=alert.get("attack_type", "Unknown"),
            severity=severity,
            src_ip=alert.get("src_ip", "Unknown"),
            detail=alert.get("detail", ""),
        )

        try:
            self._queue.put_nowait((alert, record))
        except Exception:
            logger.warning("Alert queue full — dropping alert for %s", aid)
            return None

        with self._lock:
            self._records.append(record)

        return record

    def dispatch_sync(self, alert: dict) -> Optional[AlertRecord]:
        """
        Dispatch an alert synchronously (blocks until all channels attempted).
        Use only in tests or when guaranteed delivery is required.
        """
        severity = alert.get("severity", "INFO")
        sev_idx  = _SEVERITY_ORDER.index(severity) \
                   if severity in _SEVERITY_ORDER else 0
        if sev_idx < self._min_sev_idx:
            return None

        aid = _alert_id(alert)
        now = time.monotonic()
        with self._lock:
            last = self._dedup.get(aid, 0.0)
            if now - last < _DEDUP_WINDOW_S:
                return None
            self._dedup[aid] = now

        record = AlertRecord(
            alert_id=f"ALT-{int(time.time() * 1000)}",
            timestamp=alert.get("timestamp", datetime.now(tz=timezone.utc)),
            attack_type=alert.get("attack_type", "Unknown"),
            severity=severity,
            src_ip=alert.get("src_ip", "Unknown"),
            detail=alert.get("detail", ""),
        )
        self._send_all(alert, record)
        with self._lock:
            self._records.append(record)
        return record

    # ------------------------------------------------------------------
    # Channel senders
    # ------------------------------------------------------------------

    def _send_all(self, alert: dict, record: AlertRecord) -> None:
        """Send to all configured channels in parallel threads."""
        threads = []

        if self._slack_url:
            t = threading.Thread(
                target=self._send_slack, args=(alert, record), daemon=True
            )
            threads.append(t)

        if self._email_to:
            t = threading.Thread(
                target=self._send_email, args=(alert, record), daemon=True
            )
            threads.append(t)

        if self._webhook_url:
            t = threading.Thread(
                target=self._send_webhook, args=(alert, record), daemon=True
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=_WORKER_TIMEOUT_S)

        self._audit(record)

    def _send_slack(self, alert: dict, record: AlertRecord) -> None:
        try:
            payload = _format_slack(alert)
            resp = requests.post(
                self._slack_url,
                json=payload,
                timeout=_WORKER_TIMEOUT_S,
            )
            if resp.status_code == 200:
                record.channels_sent.append("slack")
                logger.info("Slack alert sent for %s", record.alert_id)
            else:
                logger.warning("Slack returned %d for %s", resp.status_code, record.alert_id)
        except requests.RequestException as exc:
            logger.error("Slack send failed: %s", exc)

    def _send_email(self, alert: dict, record: AlertRecord) -> None:
        try:
            body = _format_text(alert)
            msg  = MIMEText(body, "plain")
            msg["Subject"] = f"[SENTINEL] {alert.get('severity','?')} — {alert.get('attack_type','?')}"
            msg["From"]    = self._email_from
            msg["To"]      = ", ".join(self._email_to)

            with smtplib.SMTP(self._smtp_host, self._smtp_port,
                              timeout=_WORKER_TIMEOUT_S) as smtp:
                if self._smtp_user:
                    smtp.login(self._smtp_user, self._smtp_pass)
                smtp.sendmail(self._email_from, self._email_to, msg.as_string())

            record.channels_sent.append("email")
            logger.info("Email alert sent for %s", record.alert_id)
        except smtplib.SMTPException as exc:
            logger.error("SMTP send failed: %s", exc)
        except OSError as exc:
            logger.error("Email connection failed: %s", exc)

    def _send_webhook(self, alert: dict, record: AlertRecord) -> None:
        try:
            payload = {
                "alert_id":    record.alert_id,
                "timestamp":   record.timestamp.isoformat(),
                "attack_type": record.attack_type,
                "severity":    record.severity,
                "src_ip":      record.src_ip,
                "detail":      record.detail,
                "mitre":       {
                    "technique_id": alert.get("mitre_technique_id", ""),
                    "tactic":       alert.get("mitre_tactic", ""),
                },
            }
            resp = requests.post(
                self._webhook_url,
                json=payload,
                timeout=_WORKER_TIMEOUT_S,
            )
            if resp.status_code < 300:
                record.channels_sent.append("webhook")
                logger.info("Webhook alert sent for %s", record.alert_id)
            else:
                logger.warning("Webhook returned %d", resp.status_code)
        except requests.RequestException as exc:
            logger.error("Webhook send failed: %s", exc)

    def _audit(self, record: AlertRecord) -> None:
        try:
            line = json.dumps({
                "alert_id":     record.alert_id,
                "timestamp":    record.timestamp.isoformat(),
                "attack_type":  record.attack_type,
                "severity":     record.severity,
                "src_ip":       record.src_ip,
                "channels":     record.channels_sent,
            }) + "\n"
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.error("Alert audit write failed: %s", exc)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def recent_alerts(self, n: int = 50) -> list[AlertRecord]:
        """Return the n most recently dispatched alert records."""
        with self._lock:
            return list(self._records[-n:])

    def alert_count(self) -> int:
        with self._lock:
            return len(self._records)
