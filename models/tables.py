"""
tables.py — SQLAlchemy ORM table definitions.

Tables:
  - Scan        : one row per nmap scan run
  - Device      : one row per unique device ever seen (MAC-keyed when possible)
  - ScanDevice  : snapshot of a device within one specific scan
  - ChangeEvent : one row per detected change between two adjacent scans
  - Alert       : user-facing notifications (new device seen for first time)
  - Setting     : key/value config store
  - HealthCheck : one row per internet connectivity/latency check
  - SpeedTest   : one row per on-demand speed test result
  - AISummary   : one row per AI analysis run
  - ActivityLog : audit trail — every automated action, scan, AI verdict, firewall change
"""

import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    """Return current UTC time. Used as a column default."""
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id         = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=utcnow)
    ended_at   = Column(DateTime, nullable=True)
    duration_s = Column(Float, nullable=True)
    host_count = Column(Integer, default=0)
    status     = Column(String, default="running")   # "running" | "complete" | "failed"
    error      = Column(Text, nullable=True)

    devices       = relationship("ScanDevice",  back_populates="scan")
    change_events = relationship(
        "ChangeEvent",
        foreign_keys="ChangeEvent.scan_id",
        back_populates="scan",
    )


class Device(Base):
    __tablename__ = "devices"

    id         = Column(Integer, primary_key=True, index=True)
    mac        = Column(String, unique=True, index=True, nullable=True)
    vendor     = Column(String, nullable=True)
    hostname   = Column(String, nullable=True)   # latest known
    first_seen = Column(DateTime, default=utcnow)
    last_seen  = Column(DateTime, default=utcnow, onupdate=utcnow)
    label      = Column(String, nullable=True)
    is_known   = Column(Boolean, default=False)

    # ── Phase 0/1: per-device baseline + allow-list ─────────────────────────
    # known_ports_json     — JSON list of int ports that are the device's
    #                        accepted baseline. Set when (a) a deep scan
    #                        confirms ports, or (b) the user accepts a
    #                        port-change alert.
    # allow_json           — JSON {"allowed_ports":[], "allowed_destinations":[],
    #                        "allowed_high_bandwidth": bool}. Suppresses
    #                        anomaly alerts when behavior matches.
    # baseline_set_at      — when known_ports_json was last frozen/updated.
    known_ports_json = Column(Text, nullable=True)
    allow_json       = Column(Text, nullable=True)
    baseline_set_at  = Column(DateTime, nullable=True)

    # Best-known OS string + when it was learned. Populated by AI investigate
    # (nmap -O / SSDP / SMB / banner-grab) and surfaced in the devices table.
    os_guess    = Column(String, nullable=True)
    os_guess_at = Column(DateTime, nullable=True)

    # DHCP Fingerprint fields
    dhcp_option55 = Column(String, nullable=True)
    dhcp_option60 = Column(String, nullable=True)
    dhcp_hostname = Column(String, nullable=True)

    appearances = relationship("ScanDevice", back_populates="device")


class ScanDevice(Base):
    """Snapshot of one device within one specific scan."""
    __tablename__ = "scan_devices"

    id        = Column(Integer, primary_key=True, index=True)
    scan_id   = Column(Integer, ForeignKey("scans.id"),   nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    ip         = Column(String, nullable=True)
    hostname   = Column(String, nullable=True)   # historical snapshot (added Phase 3)
    open_ports = Column(Text, default="[]")
    services_json = Column(Text, nullable=True)
    cves_json     = Column(Text, nullable=True)

    scan   = relationship("Scan",   back_populates="devices")
    device = relationship("Device", back_populates="appearances")

    @property
    def ports_list(self):
        return json.loads(self.open_ports or "[]")

    @property
    def services_list(self):
        return json.loads(self.services_json or "[]")

    @property
    def cves_list(self):
        return json.loads(self.cves_json or "[]")


class ChangeEvent(Base):
    """One detected change between two adjacent completed scans."""
    __tablename__ = "change_events"

    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(Integer, ForeignKey("scans.id"), nullable=False)
    prev_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    device_id    = Column(Integer, ForeignKey("devices.id"), nullable=True)
    change_type  = Column(String, nullable=False)
    message      = Column(Text, nullable=False)
    detail       = Column(Text, default="{}")
    created_at   = Column(DateTime, default=utcnow)

    scan = relationship("Scan", foreign_keys=[scan_id], back_populates="change_events")


class Alert(Base):
    __tablename__ = "alerts"

    id         = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=utcnow)
    alert_type = Column(String, nullable=False)
    message    = Column(Text, nullable=False)
    read       = Column(Boolean, default=False)
    device_id  = Column(Integer, ForeignKey("devices.id"), nullable=True)


class Setting(Base):
    """
    Key/value configuration store.

    Default settings (seeded on first startup in main.py):
      health_check_interval_s  — seconds between automatic health checks (default 300)
      health_target            — IP/host to ping (default 8.8.8.8)
      latency_warn_ms          — latency above this = "degraded" (default 100)
      latency_crit_ms          — latency above this = informational (default 300)
      packet_loss_warn_pct     — loss % above this = "degraded" (default 10)
      health_alerts_enabled    — whether to create Alert rows for outages (default true)
      speed_test_url           — URL for download speed test
    """
    __tablename__ = "settings"

    id    = Column(Integer, primary_key=True, index=True)
    key   = Column(String, unique=True, nullable=False)
    value = Column(Text, nullable=True)


class HealthCheck(Base):
    """
    One row per internet health check.
    Written by the background scheduler (monitoring/scheduler.py).

    status values:
      "online"   — all packets received, latency within normal range
      "degraded" — high latency or some packet loss
      "offline"  — 100% packet loss

    Retention: capped at ~2000 rows (see scheduler.py pruning logic).
    At a 5-minute interval that's ~7 days of history.
    At a 1-minute interval that's ~33 hours.
    """
    __tablename__ = "health_checks"

    id              = Column(Integer, primary_key=True, index=True)
    checked_at      = Column(DateTime, default=utcnow, index=True)
    status          = Column(String, nullable=False)      # "online" | "degraded" | "offline"
    latency_ms      = Column(Float, nullable=True)        # internet RTT (8.8.8.8 or configured)
    local_latency_ms = Column(Float, nullable=True)       # router RTT (local network)
    packet_loss     = Column(Float, nullable=True)        # 0–100 percentage
    target          = Column(String, default="8.8.8.8")  # internet host pinged
    local_target    = Column(String, nullable=True)       # router/gateway IP
    error           = Column(Text, nullable=True)         # error description if offline


class SpeedTest(Base):
    """
    One row per on-demand speed test (download + upload).
    Triggered manually from the dashboard, not by the scheduler.
    """
    __tablename__ = "speed_tests"

    id            = Column(Integer, primary_key=True, index=True)
    tested_at     = Column(DateTime, default=utcnow)
    download_mbps = Column(Float, nullable=True)
    upload_mbps   = Column(Float, nullable=True)
    latency_ms    = Column(Float, nullable=True)
    error         = Column(Text, nullable=True)


class CaptureSession(Base):
    """
    One row per dumpcap capture run.
    Tracks interface, ring-buffer settings, status, and any error.
    """
    __tablename__ = "capture_sessions"

    id           = Column(Integer, primary_key=True, index=True)
    started_at   = Column(DateTime, default=utcnow, index=True)
    stopped_at   = Column(DateTime, nullable=True)
    interface    = Column(String,  nullable=True)
    status       = Column(String,  default="running")  # running | stopped | error
    file_path    = Column(String,  nullable=True)       # base path for ring files
    file_size_mb = Column(Integer, nullable=True)
    file_count   = Column(Integer, nullable=True)
    error        = Column(Text,    nullable=True)


class TrafficSummary(Base):
    """
    Periodic traffic analysis snapshot.
    Written by the background scheduler while capture is running.
    Metadata only — no packet payload is stored.
    """
    __tablename__ = "traffic_summaries"

    id               = Column(Integer, primary_key=True, index=True)
    created_at       = Column(DateTime, default=utcnow, index=True)
    session_id       = Column(Integer, ForeignKey("capture_sessions.id"), nullable=True)
    total_packets    = Column(Integer, nullable=True)
    total_bytes      = Column(Integer, nullable=True)
    files_analyzed   = Column(Integer, default=0)
    top_talkers      = Column(Text, default="[]")   # JSON [{ip,bytes,packets,mb}]
    top_destinations = Column(Text, default="[]")   # JSON [{ip,bytes,packets,mb}]
    protocol_mix     = Column(Text, default="{}")   # JSON {PROTO: count}
    dns_count        = Column(Integer, default=0)
    top_domains      = Column(Text, default="[]")   # JSON [{domain,count}] — DNS+TLS+HTTP hostnames
    error            = Column(Text, nullable=True)


class AISummary(Base):
    """
    One row per AI analysis run.

    The AI reads structured monitoring data and produces a plain-English
    assessment. We persist it here so:
      - The dashboard can show the last result without re-running
      - The user can see how the AI's assessments change over time
      - We can track token usage

    AI is fully optional — if ai_enabled=false or the provider is
    unavailable, no rows are written and the app works unchanged.

    Columns:
      scan_id       — which scan was analysed (nullable: could be health-only)
      provider      — "anthropic", "openai", etc.
      model         — specific model string used
      summary       — 1-3 sentence plain-English assessment
      severity      — "low" | "medium" | "high"
      benign        — JSON array of normal-looking observations
      concerning    — JSON array of observations worth attention
      next_steps    — JSON array of actionable recommendations
      raw_response  — full model output text (for debugging)
      input_tokens  — tokens sent (for cost tracking)
      output_tokens — tokens received (for cost tracking)
      error         — set if analysis failed; other fields may be null
    """
    __tablename__ = "ai_summaries"

    id            = Column(Integer, primary_key=True, index=True)
    created_at    = Column(DateTime, default=utcnow, index=True)
    scan_id       = Column(Integer, ForeignKey("scans.id"), nullable=True)
    provider      = Column(String,  nullable=True)
    model         = Column(String,  nullable=True)
    summary       = Column(Text,    nullable=True)
    severity      = Column(String,  nullable=True)   # low | medium | high
    benign        = Column(Text,    default="[]")    # JSON array
    concerning    = Column(Text,    default="[]")    # JSON array
    next_steps    = Column(Text,    default="[]")    # JSON array
    raw_response  = Column(Text,    nullable=True)   # full model output
    input_tokens  = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    error         = Column(Text,    nullable=True)


class SecurityReport(Base):
    """
    One row per autonomous AI security report (generated hourly by Qwen).
    Analyzes the last hour of network data and produces a plain-English assessment.
    """
    __tablename__ = "security_reports"

    id           = Column(Integer, primary_key=True, index=True)
    created_at   = Column(DateTime, default=utcnow, index=True)
    report_type  = Column(String, default="hourly")    # "hourly" | "incident"
    period_start = Column(DateTime, nullable=True)
    period_end   = Column(DateTime, nullable=True)
    severity     = Column(String, default="low")       # "low" | "medium" | "high" | "critical"
    headline     = Column(String, nullable=True)       # one-line summary
    body         = Column(Text, nullable=True)         # full report text
    anomalies    = Column(Text, default="[]")           # JSON array of strings
    recommendations = Column(Text, default="[]")        # JSON array of strings
    model        = Column(String, nullable=True)
    error        = Column(Text, nullable=True)


class ActivityLog(Base):
    """
    Unified audit trail for all automated actions, scans, AI verdicts,
    firewall changes, and threat detections.

    level values:
      info     — routine event (scan ran, device seen, traffic summarized)
      warning  — something worth noting (new unknown device, high latency, suspicious traffic)
      critical — threat detected or serious anomaly
      action   — a change was made (label applied, firewall rule added/removed)
      threat   — confirmed threat intel hit

    category values:
      scan     — nmap scans and device discovery
      traffic  — packet capture and traffic analysis events
      ai       — Qwen investigation verdicts and auto-execute results
      firewall — block/unblock firewall rule changes
      threat   — threat intelligence matches
      system   — service lifecycle (startup, capture start/stop, etc.)
      alert    — alert creation and dismissal

    Retention: capped at 10,000 rows (oldest pruned). At ~50 events/day
    that's ~200 days of history.
    """
    __tablename__ = "activity_log"

    id          = Column(Integer, primary_key=True, index=True)
    created_at  = Column(DateTime, default=utcnow, index=True)
    level       = Column(String, default="info",   nullable=False)
    category    = Column(String, nullable=False)
    event       = Column(String, nullable=False)
    summary     = Column(String, nullable=False)
    detail      = Column(Text,   nullable=True)
    device_ip   = Column(String, nullable=True, index=True)
    device_id   = Column(Integer, ForeignKey("devices.id"), nullable=True)
    dismissed   = Column(Boolean, default=False)
    # Autonomous-action tracking. actor distinguishes who/what initiated the
    # event ("user", "anomaly_auto", "ai_auto", "ntfy_command", "system").
    # revert_json stores a JSON {action_type, params} payload that ai_resolve()
    # can replay to undo this action; null means the row isn't reversible.
    # reverted_at / reverted_by are filled when a revert is applied.
    actor       = Column(String, default="system", nullable=False, index=True)
    revert_json = Column(Text,   nullable=True)
    reverted_at = Column(DateTime, nullable=True)
    reverted_by = Column(String, nullable=True)


class DeviceCountryHistory(Base):
    """
    Per-device record of countries each device has communicated with.
    Used by Phase 2 geo-anomaly detection: a device suddenly reaching a
    country it has never reached before is flagged as suspicious.
    """
    __tablename__ = "device_country_history"

    id          = Column(Integer, primary_key=True, index=True)
    device_id   = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    country     = Column(String, nullable=False, index=True)
    first_seen  = Column(DateTime, default=utcnow)
    last_seen   = Column(DateTime, default=utcnow)
    total_bytes = Column(Integer, default=0)


class IncidentCapture(Base):
    """
    Phase 4: A pcap snippet extracted from the rolling ring buffer around an
    anomaly event. Survives ring-buffer rotation. Lets the user replay exactly
    what was on the wire when an incident fired.
    """
    __tablename__ = "incident_captures"

    id              = Column(Integer, primary_key=True, index=True)
    created_at      = Column(DateTime, default=utcnow, index=True)
    anomaly_log_id  = Column(Integer, ForeignKey("activity_log.id"), nullable=True)
    file_path       = Column(String, nullable=False)
    file_size_bytes = Column(Integer, default=0)
    packet_count    = Column(Integer, default=0)
    window_start    = Column(DateTime, nullable=True)
    window_end      = Column(DateTime, nullable=True)
    summary_json    = Column(Text, default="{}")
    anomaly_type    = Column(String, nullable=True)
    device_ip       = Column(String, nullable=True, index=True)


class HuntRule(Base):
    """
    Phase 8: User-defined hunt-mode rules. Stored as a name + YAML body that
    the rule engine evaluates every minute against current network state.
    """
    __tablename__ = "hunt_rules"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    yaml_body   = Column(Text, nullable=False)
    enabled     = Column(Boolean, default=True)
    severity    = Column(String, default="warning")   # info | warning | critical
    created_at  = Column(DateTime, default=utcnow)
    updated_at  = Column(DateTime, default=utcnow, onupdate=utcnow)
    last_fired_at = Column(DateTime, nullable=True)
    fire_count    = Column(Integer, default=0)


# ── Security Lab ───────────────────────────────────────────────────────────────

class SecurityToolRun(Base):
    __tablename__ = "security_tool_runs"
    id                    = Column(Integer, primary_key=True, index=True)
    tool                  = Column(String, nullable=False, index=True)
    tab                   = Column(String, nullable=True)
    target                = Column(String, nullable=True, index=True)
    target_type           = Column(String, nullable=True)
    device_id             = Column(Integer, ForeignKey("devices.id"), nullable=True)
    status                = Column(String, default="queued", index=True)
    is_attack_tool        = Column(Boolean, default=False)
    authorization_confirmed = Column(Boolean, default=False)
    params_json           = Column(Text, nullable=True)
    command_json          = Column(Text, nullable=True)
    exit_code             = Column(Integer, nullable=True)
    raw_output_text       = Column(Text, nullable=True)
    error_message         = Column(Text, nullable=True)
    risk_level            = Column(String, nullable=True)
    created_at            = Column(DateTime, default=utcnow)
    started_at            = Column(DateTime, nullable=True)
    completed_at          = Column(DateTime, nullable=True)
    duration_seconds      = Column(Float, nullable=True)


class SecurityToolOutputChunk(Base):
    __tablename__ = "security_tool_output_chunks"
    id         = Column(Integer, primary_key=True, index=True)
    run_id     = Column(Integer, ForeignKey("security_tool_runs.id"), nullable=False, index=True)
    sequence   = Column(Integer, default=0)
    stream     = Column(String, nullable=False)
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class SecurityAIExplanation(Base):
    __tablename__ = "security_ai_explanations"
    id                    = Column(Integer, primary_key=True, index=True)
    run_id                = Column(Integer, ForeignKey("security_tool_runs.id"), unique=True, index=True)
    provider              = Column(String, default="ollama")
    model                 = Column(String, nullable=True)
    summary_text          = Column(Text, nullable=False)
    findings_json         = Column(Text, nullable=True)
    recommendations_json  = Column(Text, nullable=True)
    raw_ai_response       = Column(Text, nullable=True)
    created_at            = Column(DateTime, default=utcnow)


class SecurityFile(Base):
    __tablename__ = "security_files"
    id            = Column(Integer, primary_key=True, index=True)
    run_id        = Column(Integer, ForeignKey("security_tool_runs.id"), nullable=True, index=True)
    file_type     = Column(String, nullable=False)
    original_name = Column(String, nullable=True)
    storage_path  = Column(String, nullable=False)
    sha256        = Column(String, nullable=False, index=True)
    size_bytes    = Column(Integer, nullable=False)
    created_at    = Column(DateTime, default=utcnow)


class SecurityWSLCheck(Base):
    __tablename__ = "security_wsl_checks"
    id                   = Column(Integer, primary_key=True, index=True)
    wsl_installed        = Column(Boolean, default=False)
    default_distro       = Column(String, nullable=True)
    distro_list_text     = Column(Text, nullable=True)
    tools_json           = Column(Text, nullable=True)
    install_command_text = Column(Text, nullable=True)
    created_at           = Column(DateTime, default=utcnow)


class ShodanExposureResult(Base):
    __tablename__ = "shodan_exposure_results"
    id                = Column(Integer, primary_key=True, index=True)
    run_id            = Column(Integer, ForeignKey("security_tool_runs.id"), nullable=False, index=True)
    target_ip         = Column(String, nullable=True)
    query_ip          = Column(String, nullable=False, index=True)
    is_private_target = Column(Boolean, default=False)
    exposed           = Column(Boolean, default=False)
    org               = Column(String, nullable=True)
    isp               = Column(String, nullable=True)
    country           = Column(String, nullable=True)
    ports_json        = Column(Text, nullable=True)
    vulns_json        = Column(Text, nullable=True)
    raw_json          = Column(Text, nullable=True)
    created_at        = Column(DateTime, default=utcnow)


class WifiSecurityResult(Base):
    __tablename__ = "wifi_security_results"
    id                  = Column(Integer, primary_key=True, index=True)
    run_id              = Column(Integer, ForeignKey("security_tool_runs.id"), nullable=False, index=True)
    interface           = Column(String, nullable=True)
    ssid                = Column(String, nullable=True)
    bssid               = Column(String, nullable=True)
    channel             = Column(String, nullable=True)
    capture_path        = Column(String, nullable=True)
    handshake_detected  = Column(Boolean, nullable=True)
    cracking_attempted  = Column(Boolean, default=False)
    cracked             = Column(Boolean, nullable=True)
    created_at          = Column(DateTime, default=utcnow)


class DeviceChat(Base):
    """
    One row per turn in the interactive AI investigation chat for a device.
    Roles: "user" | "assistant" | "tool" | "system"
    Pruned at ~200 turns/device — oldest summarized into a DeviceNote and dropped.
    """
    __tablename__ = "device_chats"

    id         = Column(Integer, primary_key=True, index=True)
    device_id  = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    role       = Column(String, nullable=False)        # user | assistant | tool | system
    content    = Column(Text,   nullable=False)
    # Optional structured payload (tool call result, proposal, etc.)
    meta_json  = Column(Text, nullable=True)


class DeviceNote(Base):
    """
    Distilled, durable facts the AI has learned about a device across all
    investigation chats. Survive chat-history pruning. Examples:
      "WireGuard endpoint = mullvad.net"
      "talks to push.apple.com daily — likely iPhone"
      "MAC is randomized (locally administered bit set)"
    """
    __tablename__ = "device_notes"

    id         = Column(Integer, primary_key=True, index=True)
    device_id  = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    kind       = Column(String, default="fact")        # fact | identity | scan | summary
    body       = Column(Text, nullable=False)
    # Confidence 0.0–1.0 (for identity facts); null for plain facts.
    confidence = Column(Float, nullable=True)
    # Source: "chat" | "tool:nmap" | "tool:tshark" | "user" | "summary"
    source     = Column(String, nullable=True)


class PasswordCrackResult(Base):
    __tablename__ = "password_crack_results"
    id                  = Column(Integer, primary_key=True, index=True)
    run_id              = Column(Integer, ForeignKey("security_tool_runs.id"), nullable=False, index=True)
    hash_count          = Column(Integer, nullable=True)
    cracked_count       = Column(Integer, nullable=True)
    cracked_items_json  = Column(Text, nullable=True)
    john_format         = Column(String, nullable=True)
    created_at          = Column(DateTime, default=utcnow)
