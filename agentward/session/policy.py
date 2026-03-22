"""Session monitoring policy configuration.

Defines ``SessionPolicy`` — the Pydantic model that controls whether
session-level evasion detection is active and what actions to take when
threats are detected.

Integrate into agentward.yaml::

    session:
      enabled: true
      sensitivity: medium
      window_size: 50
      session_ttl: 3600
      on_suspicious: warn
      on_evasion: block
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class SessionSensitivity(str, Enum):
    """Sensitivity level for session-level evasion detection.

    LOW:    High threshold — fewer false positives, misses subtle attacks.
    MEDIUM: Balanced — recommended default for most deployments.
    HIGH:   Low threshold — catches more attacks at the cost of more noise.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SessionAction(str, Enum):
    """Actions available when a session verdict is triggered.

    LOG:   Record the event in the audit trail; no impact on the call.
    WARN:  Log + print a warning to stderr; the call still proceeds.
    PAUSE: Block all further calls from this session until manually cleared.
    BLOCK: Block the call that triggered the verdict.
    """

    LOG = "log"
    WARN = "warn"
    PAUSE = "pause"
    BLOCK = "block"


class SessionPolicy(BaseModel):
    """Configuration for the session-level evasion detection system.

    The session monitor observes sequences of tool calls and flags patterns
    that constitute multi-step attacks even when no individual call violates
    per-call policy.

    This feature is opt-in (``enabled: false`` by default) to have zero
    impact on existing deployments.

    Example — standard mode::

        session:
          enabled: true
          sensitivity: medium
          on_suspicious: warn
          on_evasion: block

    Example — high-security mode::

        session:
          enabled: true
          sensitivity: high
          window_size: 30
          session_ttl: 1800
          on_suspicious: warn
          on_evasion: block
    """

    enabled: bool = Field(
        default=False,
        description=(
            "Enable session-level evasion detection. "
            "Opt-in — default false to avoid impacting existing deployments."
        ),
    )
    sensitivity: SessionSensitivity = Field(
        default=SessionSensitivity.MEDIUM,
        description=(
            "Detection sensitivity level. "
            "low: fewer false positives. "
            "high: catches more attacks, noisier."
        ),
    )
    window_size: int = Field(
        default=50,
        ge=5,
        le=500,
        description="Maximum tool calls to retain per session for pattern analysis.",
    )
    session_ttl: int = Field(
        default=3600,
        ge=60,
        description=(
            "Seconds of inactivity before a session is expired and its "
            "buffer cleared. Prevents unbounded memory growth."
        ),
    )
    on_suspicious: SessionAction = Field(
        default=SessionAction.WARN,
        description=(
            "Action when a SUSPICIOUS verdict is returned. "
            "log: audit only. warn: log + stderr warning, call proceeds. "
            "pause: block session. Default: warn."
        ),
    )
    on_evasion: SessionAction = Field(
        default=SessionAction.BLOCK,
        description=(
            "Action when EVASION_DETECTED is returned. "
            "log: audit only. block: reject the triggering call. "
            "pause: block session. Default: block."
        ),
    )
