"""Configuration for the Perceptor SSVC classification engine."""

from __future__ import annotations

PERCEPTOR_CONTEXT_WINDOW_KEY = "perceptor"
PERCEPTOR_CONTEXT_WINDOW_MAX_TOKENS = 15000
PERCEPTOR_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS = 15000

# Hard bounds for input/output token safety.
PERCEPTOR_MAX_INPUT_CHARS = 16000
PERCEPTOR_MAX_SUMMARY_CHARS = 480

# SSVC decision thresholds.
ACT_MIN_CVSS = 9.0
ATTEND_MIN_CVSS = 7.0
ACT_MIN_EPSS = 0.20
ATTEND_MIN_EPSS = 0.05

# Score interpretation:
# >= 0.78 => ACT
# >= 0.42 => ATTEND
# else TRACK
ACT_MIN_SCORE = 0.78
ATTEND_MIN_SCORE = 0.42
