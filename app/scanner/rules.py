import re
import math
import json
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Pattern
from app.config import settings

logger = logging.getLogger("hs_wss.rules")


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string to evaluate randomness."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for c in data:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(value: str) -> str:
    """
    Safely masks a secret string, keeping prefix and suffix for identification
    while obscuring sensitive characters.
    Example: ABCDEFGHIJKLMNOPQRST -> ABCD****************QRST
    """
    val = value.strip()
    length = len(val)
    if length <= 8:
        return "*" * max(length, 4)
    if length <= 16:
        return f"{val[:2]}{'*' * (length - 4)}{val[-2:]}"
    # Standard mask: keep 4 chars at beginning and 4 chars at end
    prefix_len = 4
    suffix_len = 4
    masked_middle = "*" * (length - prefix_len - suffix_len)
    return f"{val[:prefix_len]}{masked_middle}{val[-suffix_len:]}"


def extract_context_snippet(content: str, match_start: int, match_end: int, secret_value: str, masked_value: str, window: int = 50) -> str:
    """
    Extracts a sanitized context snippet around the match location.
    The raw secret within the snippet is completely replaced by the masked value.
    """
    start = max(0, match_start - window)
    end = min(len(content), match_end + window)
    prefix = content[start:match_start].replace("\r", " ").replace("\n", " ").strip()
    suffix = content[match_end:end].replace("\r", " ").replace("\n", " ").strip()
    
    # Ellipsis indicators
    left_ellipsis = "..." if start > 0 else ""
    right_ellipsis = "..." if end < len(content) else ""
    
    return f"{left_ellipsis}{prefix} [{masked_value}] {suffix}{right_ellipsis}".strip()


@dataclass
class SecretRule:
    id: str
    name: str
    pattern: Pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    capture_group: int = 0
    entropy_threshold: Optional[float] = None
    min_length: int = 8

    def evaluate(self, match: re.Match) -> Optional[str]:
        """Extracts and validates matched secret value. Returns secret if valid, else None."""
        try:
            val = match.group(self.capture_group)
        except IndexError:
            val = match.group(0)

        if not val or len(val) < self.min_length:
            return None

        # Ignore common non-secret dummy placeholders or syntax
        val_lower = val.lower()
        common_false_positives = {
            "true", "false", "undefined", "null", "none", "nan",
            "example", "your_api_key_here", "changeme", "placeholder",
            "localhost", "application/json", "text/javascript",
            "0000000000000000", "1111111111111111", "1234567890123456"
        }
        if val_lower in common_false_positives:
            return None

        # Check entropy if configured for generic patterns
        if self.entropy_threshold is not None:
            entropy = shannon_entropy(val)
            if entropy < self.entropy_threshold:
                return None

        return val


# Default high-fidelity regex rules for DevSecOps secret scanning
DEFAULT_RULES: List[SecretRule] = [
    SecretRule(
        id="aws-access-key-id",
        name="AWS Access Key ID",
        pattern=re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        severity="CRITICAL",
        description="Amazon Web Services 20-character Access Key ID identifier.",
        capture_group=1
    ),
    SecretRule(
        id="aws-secret-access-key",
        name="AWS Secret Access Key",
        pattern=re.compile(r"(?i)\b(?:aws_secret_access_key|aws_sec_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        severity="CRITICAL",
        description="Amazon Web Services 40-character Secret Access Key.",
        capture_group=1,
        entropy_threshold=3.5
    ),
    SecretRule(
        id="github-token",
        name="GitHub Personal Access Token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
        severity="CRITICAL",
        description="GitHub personal, oauth, or user-to-server access token.",
        capture_group=1
    ),
    SecretRule(
        id="google-api-key",
        name="Google Cloud / Firebase API Key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity="HIGH",
        description="Google Cloud Platform or Firebase public/private API key.",
        capture_group=1
    ),
    SecretRule(
        id="slack-token",
        name="Slack API Token",
        pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
        severity="HIGH",
        description="Slack bot, user, or app authorization token.",
        capture_group=1
    ),
    SecretRule(
        id="slack-webhook",
        name="Slack Incoming Webhook URL",
        pattern=re.compile(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)"),
        severity="HIGH",
        description="Slack Incoming Webhook URL granting channel write access.",
        capture_group=1
    ),
    SecretRule(
        id="stripe-api-key",
        name="Stripe Live API Key",
        pattern=re.compile(r"\b([sr]k_live_[0-9a-zA-Z]{24,99})\b"),
        severity="CRITICAL",
        description="Stripe live secret or restricted API key for payment operations.",
        capture_group=1
    ),
    SecretRule(
        id="private-key",
        name="Private Cryptographic Key",
        pattern=re.compile(r"(-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----)"),
        severity="CRITICAL",
        description="Unencrypted RSA, EC, DSA, or OpenSSH private cryptographic key.",
        capture_group=1,
        min_length=64
    ),
    SecretRule(
        id="jwt-token",
        name="JSON Web Token (JWT)",
        pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+)\b"),
        severity="MEDIUM",
        description="Signed or unsigned JSON Web Token containing claims and credentials.",
        capture_group=1,
        min_length=30
    ),
    SecretRule(
        id="database-uri",
        name="Database Connection String with Credentials",
        pattern=re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis|amqp)://[a-zA-Z0-9_.\-]+:([^@\s'\"]+)@[a-zA-Z0-9_.\-]+:[0-9]+(?:/[a-zA-Z0-9_.\-]*)?)\b"),
        severity="CRITICAL",
        description="Database connection URI exposing username, password, host, and port.",
        capture_group=1
    ),
    SecretRule(
        id="generic-api-key",
        name="Generic API Key / High-Entropy Secret",
        pattern=re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|app[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,80})['\"]"),
        severity="HIGH",
        description="General high-entropy credential assigned to API key or secret variable.",
        capture_group=1,
        entropy_threshold=3.6,
        min_length=20
    ),
    SecretRule(
        id="generic-password-assignment",
        name="Hardcoded Password Variable",
        pattern=re.compile(r"(?i)\b(?:password|passwd|pwd|db_pass)\s*[:=]\s*['\"]([^'\"\s]{8,64})['\"]"),
        severity="MEDIUM",
        description="Potential password or secret phrase assigned in source code.",
        capture_group=1,
        entropy_threshold=3.0,
        min_length=8
    )
]


def load_custom_rules() -> List[SecretRule]:
    """Loads additional custom regex rules from JSON file if configured and present."""
    custom_rules: List[SecretRule] = []
    file_path = Path(settings.CUSTOM_REGEX_FILE)
    if not file_path.exists():
        return custom_rules

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data.get("rules", []):
                rule = SecretRule(
                    id=item.get("id", "custom-rule"),
                    name=item.get("name", "Custom Rule"),
                    pattern=re.compile(item["pattern"]),
                    severity=item.get("severity", "HIGH").upper(),
                    description=item.get("description", "Custom configured secret pattern"),
                    capture_group=item.get("capture_group", 0),
                    entropy_threshold=item.get("entropy_threshold"),
                    min_length=item.get("min_length", 8)
                )
                custom_rules.append(rule)
        logger.info(f"Loaded {len(custom_rules)} custom rules from {file_path}")
    except Exception as e:
        logger.error(f"Failed to load custom rules from {file_path}: {e}")

    return custom_rules


def get_rules() -> List[SecretRule]:
    """Returns combined list of default and custom rules."""
    return DEFAULT_RULES + load_custom_rules()
