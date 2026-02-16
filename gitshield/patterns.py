"""Comprehensive pattern definitions for GitShield's native detection engine.

Replaces the gitleaks dependency with a self-contained set of compiled regex
patterns covering all major secret types: cloud provider keys, VCS tokens,
messaging platform credentials, payment processor keys, database connection
strings, private keys, JWTs, and generic high-entropy secrets.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------

ENTROPY_THRESHOLD: float = 4.0  # minimum for generic high-entropy detections


def entropy(data: str) -> float:
    """Compute Shannon entropy of *data* in bits (log base 2).

    Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0

    length = len(data)
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------------------
# Pattern dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Pattern:
    """A single secret-detection pattern."""

    id: str
    name: str
    regex: re.Pattern[str]
    description: str
    severity: str  # "critical" | "high" | "medium" | "low"
    entropy_threshold: Optional[float] = None

    def __post_init__(self) -> None:
        if self.severity not in ("critical", "high", "medium", "low"):
            raise ValueError(
                f"Invalid severity '{self.severity}' for pattern '{self.id}'"
            )


# ---------------------------------------------------------------------------
# Pattern definitions, grouped by category
# ---------------------------------------------------------------------------

# ===== AWS (5) =============================================================

_AWS_PATTERNS: List[Pattern] = [
    Pattern(
        id="aws-access-key-id",
        name="AWS Access Key ID",
        regex=re.compile(
            r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)"
        ),
        description="AWS IAM access key ID starting with AKIA",
        severity="critical",
    ),
    Pattern(
        id="aws-secret-access-key",
        name="AWS Secret Access Key",
        regex=re.compile(
            r"""(?i)(?:aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key|"""
            r"""aws_secret_access_key)\s*[:=]\s*['"]?"""
            r"""([A-Za-z0-9/+=]{40})['"]?"""
        ),
        description="AWS secret access key (40-char base64 after key name)",
        severity="critical",
        entropy_threshold=4.0,
    ),
    Pattern(
        id="aws-session-token",
        name="AWS Session Token",
        regex=re.compile(
            r"""(?i)(?:aws[_\-]?session[_\-]?token)\s*[:=]\s*['"]?"""
            r"""([A-Za-z0-9/+=]{100,})['"]?"""
        ),
        description="AWS temporary session token",
        severity="high",
    ),
    Pattern(
        id="aws-mws-auth-token",
        name="AWS MWS Auth Token",
        regex=re.compile(
            r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        ),
        description="Amazon Marketplace Web Service auth token",
        severity="critical",
    ),
    Pattern(
        id="aws-account-id",
        name="AWS Account ID in ARN",
        regex=re.compile(
            r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:(\d{12}):"
        ),
        description="AWS account ID extracted from ARN",
        severity="low",
    ),
]

# ===== GCP (3) ==============================================================

_GCP_PATTERNS: List[Pattern] = [
    Pattern(
        id="gcp-service-account-key",
        name="GCP Service Account Key",
        regex=re.compile(
            r"""(?i)"type"\s*:\s*"service_account"[^}]*"private_key"\s*:\s*"-----BEGIN """
        ),
        description="Google Cloud service account JSON key file",
        severity="critical",
    ),
    Pattern(
        id="gcp-api-key",
        name="GCP API Key",
        regex=re.compile(
            r"AIza[0-9A-Za-z\-_]{35}"
        ),
        description="Google API key starting with AIza",
        severity="high",
    ),
    Pattern(
        id="gcp-oauth-client-secret",
        name="GCP OAuth Client Secret",
        regex=re.compile(
            r"""(?i)(?:client_secret|clientsecret)\s*[:=]\s*['"]?"""
            r"""(GOCSPX-[A-Za-z0-9\-_]{28,})['"]?"""
        ),
        description="Google OAuth client secret (GOCSPX-...)",
        severity="high",
    ),
]

# ===== Azure (3) ============================================================

_AZURE_PATTERNS: List[Pattern] = [
    Pattern(
        id="azure-storage-account-key",
        name="Azure Storage Account Key",
        regex=re.compile(
            r"""(?i)(?:AccountKey|account_key|azure[_\-]?storage[_\-]?key)\s*[:=]\s*['"]?"""
            r"""([A-Za-z0-9/+=]{88})['"]?"""
        ),
        description="Azure Storage account key (88-char base64)",
        severity="critical",
    ),
    Pattern(
        id="azure-connection-string",
        name="Azure SQL Connection String",
        regex=re.compile(
            r"""(?i)(?:Server|Data\s+Source)\s*=\s*[^;]+;\s*"""
            r"""(?:User\s+Id|Uid)\s*=\s*[^;]+;\s*"""
            r"""(?:Password|Pwd)\s*=\s*[^;]{8,}"""
        ),
        description="Azure/SQL connection string with embedded credentials",
        severity="high",
    ),
    Pattern(
        id="azure-sas-token",
        name="Azure SAS Token",
        regex=re.compile(
            r"""(?:sv=\d{4}-\d{2}-\d{2}&[^&\s]*sig=[A-Za-z0-9%/+=]+)"""
        ),
        description="Azure Shared Access Signature token",
        severity="high",
    ),
]

# ===== GitHub (5) ===========================================================

_GITHUB_PATTERNS: List[Pattern] = [
    Pattern(
        id="github-pat",
        name="GitHub Personal Access Token",
        regex=re.compile(
            r"ghp_[A-Za-z0-9]{30,}"
        ),
        description="GitHub personal access token (ghp_...)",
        severity="critical",
    ),
    Pattern(
        id="github-oauth",
        name="GitHub OAuth Access Token",
        regex=re.compile(
            r"gho_[A-Za-z0-9]{30,}"
        ),
        description="GitHub OAuth access token (gho_...)",
        severity="critical",
    ),
    Pattern(
        id="github-app-token",
        name="GitHub App Installation Token",
        regex=re.compile(
            r"ghs_[A-Za-z0-9]{30,}"
        ),
        description="GitHub App installation access token (ghs_...)",
        severity="critical",
    ),
    Pattern(
        id="github-refresh-token",
        name="GitHub Refresh Token",
        regex=re.compile(
            r"ghr_[A-Za-z0-9]{30,}"
        ),
        description="GitHub OAuth refresh token (ghr_...)",
        severity="critical",
    ),
    Pattern(
        id="github-fine-grained-pat",
        name="GitHub Fine-Grained PAT",
        regex=re.compile(
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{40,}"
        ),
        description="GitHub fine-grained personal access token",
        severity="critical",
    ),
]

# ===== GitLab (3) ===========================================================

_GITLAB_PATTERNS: List[Pattern] = [
    Pattern(
        id="gitlab-personal-token",
        name="GitLab Personal Access Token",
        regex=re.compile(
            r"glpat-[A-Za-z0-9\-_]{20,}"
        ),
        description="GitLab personal access token (glpat-...)",
        severity="critical",
    ),
    Pattern(
        id="gitlab-pipeline-trigger",
        name="GitLab Pipeline Trigger Token",
        regex=re.compile(
            r"""(?i)(?:trigger[_\-]?token)\s*[:=]\s*['"]?"""
            r"""([0-9a-f]{32,})['"]?"""
        ),
        description="GitLab pipeline trigger token (hex)",
        severity="high",
    ),
    Pattern(
        id="gitlab-runner-token",
        name="GitLab Runner Registration Token",
        regex=re.compile(
            r"GR1348941[A-Za-z0-9\-_]{20,}"
        ),
        description="GitLab runner registration token",
        severity="high",
    ),
]

# ===== Slack (3) ============================================================

_SLACK_PATTERNS: List[Pattern] = [
    Pattern(
        id="slack-bot-token",
        name="Slack Bot Token",
        regex=re.compile(
            r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"
        ),
        description="Slack bot user OAuth token (xoxb-...)",
        severity="high",
    ),
    Pattern(
        id="slack-user-token",
        name="Slack User Token",
        regex=re.compile(
            r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}"
        ),
        description="Slack user OAuth token (xoxp-...)",
        severity="high",
    ),
    Pattern(
        id="slack-webhook-url",
        name="Slack Webhook URL",
        regex=re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"
        ),
        description="Slack incoming webhook URL",
        severity="high",
    ),
]

# ===== Stripe (2) ===========================================================

_STRIPE_PATTERNS: List[Pattern] = [
    Pattern(
        id="stripe-secret-key",
        name="Stripe Secret Key",
        regex=re.compile(
            r"(?:sk_live_|sk_test_)[A-Za-z0-9]{24,}"
        ),
        description="Stripe API secret key (sk_live_ or sk_test_)",
        severity="critical",
    ),
    Pattern(
        id="stripe-restricted-key",
        name="Stripe Restricted Key",
        regex=re.compile(
            r"(?:rk_live_|rk_test_)[A-Za-z0-9]{24,}"
        ),
        description="Stripe restricted API key (rk_live_ or rk_test_)",
        severity="high",
    ),
]

# ===== Twilio (2) ===========================================================

_TWILIO_PATTERNS: List[Pattern] = [
    Pattern(
        id="twilio-account-sid",
        name="Twilio Account SID",
        regex=re.compile(
            r"AC[a-f0-9]{32}"
        ),
        description="Twilio account SID (AC followed by 32 hex chars)",
        severity="high",
    ),
    Pattern(
        id="twilio-auth-token",
        name="Twilio Auth Token",
        regex=re.compile(
            r"""(?i)(?:twilio[_\-]?auth[_\-]?token|TWILIO_AUTH_TOKEN)\s*[:=]\s*['"]?"""
            r"""([a-f0-9]{32})['"]?"""
        ),
        description="Twilio auth token (32 hex chars after key name)",
        severity="critical",
    ),
]

# ===== SendGrid (1) =========================================================

_SENDGRID_PATTERNS: List[Pattern] = [
    Pattern(
        id="sendgrid-api-key",
        name="SendGrid API Key",
        regex=re.compile(
            r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"
        ),
        description="SendGrid API key (SG.xxxx.xxxx)",
        severity="critical",
    ),
]

# ===== Database URLs (3) ====================================================

_DATABASE_PATTERNS: List[Pattern] = [
    Pattern(
        id="mongodb-connection-string",
        name="MongoDB Connection String",
        regex=re.compile(
            r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s]{8,}"
        ),
        description="MongoDB connection string with embedded credentials",
        severity="critical",
    ),
    Pattern(
        id="postgresql-connection-string",
        name="PostgreSQL Connection String",
        regex=re.compile(
            r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s]{8,}"
        ),
        description="PostgreSQL connection string with embedded credentials",
        severity="critical",
    ),
    Pattern(
        id="mysql-connection-string",
        name="MySQL Connection String",
        regex=re.compile(
            r"mysql://[^:\s]+:[^@\s]+@[^\s]{8,}"
        ),
        description="MySQL connection string with embedded credentials",
        severity="critical",
    ),
]

# ===== Private Keys (4) =====================================================

_PRIVATE_KEY_PATTERNS: List[Pattern] = [
    Pattern(
        id="rsa-private-key",
        name="RSA Private Key",
        regex=re.compile(
            r"-----BEGIN RSA PRIVATE KEY-----"
        ),
        description="RSA private key in PEM format",
        severity="critical",
    ),
    Pattern(
        id="ec-private-key",
        name="EC Private Key",
        regex=re.compile(
            r"-----BEGIN EC PRIVATE KEY-----"
        ),
        description="Elliptic Curve private key in PEM format",
        severity="critical",
    ),
    Pattern(
        id="dsa-private-key",
        name="DSA Private Key",
        regex=re.compile(
            r"-----BEGIN DSA PRIVATE KEY-----"
        ),
        description="DSA private key in PEM format",
        severity="critical",
    ),
    Pattern(
        id="openssh-private-key",
        name="OpenSSH Private Key",
        regex=re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----"
        ),
        description="OpenSSH private key",
        severity="critical",
    ),
    Pattern(
        id="pgp-private-key",
        name="PGP Private Key Block",
        regex=re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ),
        description="PGP/GPG private key block",
        severity="critical",
    ),
]

# ===== JWT (1) ==============================================================

_JWT_PATTERNS: List[Pattern] = [
    Pattern(
        id="jwt-token",
        name="JSON Web Token",
        regex=re.compile(
            r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.]{10,}"
        ),
        description="JSON Web Token (three base64url-encoded segments)",
        severity="medium",
        entropy_threshold=3.5,
    ),
]

# ===== Generic / High-Entropy (7) ==========================================

_GENERIC_PATTERNS: List[Pattern] = [
    Pattern(
        id="generic-api-key",
        name="Generic API Key",
        regex=re.compile(
            r"""(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9\-_./+=]{8,64})['"]?"""
        ),
        description="Generic API key assignment (api_key=... or apikey=...)",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-secret",
        name="Generic Secret",
        regex=re.compile(
            r"""(?i)(?:secret|secret[_\-]?key)\s*[:=]\s*['"]?([A-Za-z0-9\-_./+=]{8,64})['"]?"""
        ),
        description="Generic secret assignment (secret=... or secret_key=...)",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-password",
        name="Generic Password",
        regex=re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,64})['"]?"""
        ),
        description="Generic password assignment (password=...)",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-token",
        name="Generic Token",
        regex=re.compile(
            r"""(?i)(?:token|auth[_\-]?token|access[_\-]?token)\s*[:=]\s*['"]?"""
            r"""([A-Za-z0-9\-_./+=]{8,128})['"]?"""
        ),
        description="Generic token assignment (token=... or auth_token=...)",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-private-key-value",
        name="Generic Private Key Value",
        regex=re.compile(
            r"""(?i)(?:private[_\-]?key)\s*[:=]\s*['"]?([A-Za-z0-9\-_./+=]{8,128})['"]?"""
        ),
        description="Generic private key value assignment",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-credentials",
        name="Generic Credentials",
        regex=re.compile(
            r"""(?i)(?:credentials|creds|credential)\s*[:=]\s*['"]?([^\s'"]{8,64})['"]?"""
        ),
        description="Generic credentials assignment",
        severity="medium",
        entropy_threshold=ENTROPY_THRESHOLD,
    ),
    Pattern(
        id="generic-connection-string",
        name="Generic Connection String",
        regex=re.compile(
            r"""(?i)(?:connection[_\-]?string|conn[_\-]?str)\s*[:=]\s*['"]?([^\s'"]{16,256})['"]?"""
        ),
        description="Generic connection string assignment",
        severity="medium",
        entropy_threshold=3.5,
    ),
]

# ===== Other Services (10) ==================================================

_OTHER_PATTERNS: List[Pattern] = [
    Pattern(
        id="npm-access-token",
        name="npm Access Token",
        regex=re.compile(
            r"npm_[A-Za-z0-9]{36}"
        ),
        description="npm access token (npm_...)",
        severity="critical",
    ),
    Pattern(
        id="pypi-api-token",
        name="PyPI API Token",
        regex=re.compile(
            r"pypi-[A-Za-z0-9\-_.]{10,}"
        ),
        description="PyPI API token (pypi-...)",
        severity="critical",
    ),
    Pattern(
        id="heroku-api-key",
        name="Heroku API Key",
        regex=re.compile(
            r"""(?i)(?:heroku[_\-]?api[_\-]?key|HEROKU_API_KEY)\s*[:=]\s*['"]?"""
            r"""([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""
        ),
        description="Heroku API key (UUID format)",
        severity="high",
    ),
    Pattern(
        id="telegram-bot-token",
        name="Telegram Bot Token",
        regex=re.compile(
            r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"
        ),
        description="Telegram bot token (numeric_id:alphanumeric_secret)",
        severity="high",
    ),
    Pattern(
        id="discord-bot-token",
        name="Discord Bot Token",
        regex=re.compile(
            r"[MN][A-Za-z0-9\-_]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}"
        ),
        description="Discord bot token (three dot-separated segments)",
        severity="high",
    ),
    Pattern(
        id="firebase-api-key",
        name="Firebase API Key",
        regex=re.compile(
            r"""(?i)(?:firebase[_\-]?api[_\-]?key|FIREBASE_API_KEY)\s*[:=]\s*['"]?"""
            r"""(AIza[0-9A-Za-z\-_]{35})['"]?"""
        ),
        description="Firebase API key (AIza prefix in Firebase context)",
        severity="high",
    ),
    Pattern(
        id="mailgun-api-key",
        name="Mailgun API Key",
        regex=re.compile(
            r"key-[0-9a-f]{32}"
        ),
        description="Mailgun API key (key-... followed by 32 hex chars)",
        severity="high",
    ),
    Pattern(
        id="shopify-access-token",
        name="Shopify Access Token",
        regex=re.compile(
            r"shpat_[a-fA-F0-9]{32}"
        ),
        description="Shopify admin API access token (shpat_...)",
        severity="high",
    ),
    Pattern(
        id="shopify-shared-secret",
        name="Shopify Shared Secret",
        regex=re.compile(
            r"shpss_[a-fA-F0-9]{32}"
        ),
        description="Shopify shared secret (shpss_...)",
        severity="high",
    ),
    Pattern(
        id="databricks-api-token",
        name="Databricks API Token",
        regex=re.compile(
            r"dapi[a-f0-9]{32}"
        ),
        description="Databricks personal access token (dapi...)",
        severity="high",
    ),
    Pattern(
        id="hashicorp-vault-token",
        name="HashiCorp Vault Token",
        regex=re.compile(
            r"hvs\.[A-Za-z0-9]{24,}"
        ),
        description="HashiCorp Vault service token (hvs.xxx)",
        severity="critical",
    ),
    Pattern(
        id="hashicorp-terraform-token",
        name="HashiCorp Terraform Token",
        regex=re.compile(
            r"""(?i)[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,}"""
        ),
        description="Terraform Cloud / Enterprise API token",
        severity="high",
    ),
    Pattern(
        id="doppler-api-token",
        name="Doppler API Token",
        regex=re.compile(
            r"dp\.pt\.[A-Za-z0-9]{43}"
        ),
        description="Doppler personal token (dp.pt.xxx)",
        severity="high",
    ),
    Pattern(
        id="linear-api-key",
        name="Linear API Key",
        regex=re.compile(
            r"lin_api_[A-Za-z0-9]{40}"
        ),
        description="Linear API key (lin_api_...)",
        severity="high",
    ),
    Pattern(
        id="age-secret-key",
        name="age Secret Key",
        regex=re.compile(
            r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"
        ),
        description="age encryption secret key",
        severity="critical",
    ),
]


# ---------------------------------------------------------------------------
# Aggregate PATTERNS list
# ---------------------------------------------------------------------------

PATTERNS: List[Pattern] = (
    _AWS_PATTERNS
    + _GCP_PATTERNS
    + _AZURE_PATTERNS
    + _GITHUB_PATTERNS
    + _GITLAB_PATTERNS
    + _SLACK_PATTERNS
    + _STRIPE_PATTERNS
    + _TWILIO_PATTERNS
    + _SENDGRID_PATTERNS
    + _DATABASE_PATTERNS
    + _PRIVATE_KEY_PATTERNS
    + _JWT_PATTERNS
    + _GENERIC_PATTERNS
    + _OTHER_PATTERNS
)
"""All detection patterns. Iterate this to scan content."""


# ---------------------------------------------------------------------------
# Category lookup for grouping / filtering
# ---------------------------------------------------------------------------

PATTERN_CATEGORIES: dict[str, List[Pattern]] = {
    "aws": _AWS_PATTERNS,
    "gcp": _GCP_PATTERNS,
    "azure": _AZURE_PATTERNS,
    "github": _GITHUB_PATTERNS,
    "gitlab": _GITLAB_PATTERNS,
    "slack": _SLACK_PATTERNS,
    "stripe": _STRIPE_PATTERNS,
    "twilio": _TWILIO_PATTERNS,
    "sendgrid": _SENDGRID_PATTERNS,
    "database": _DATABASE_PATTERNS,
    "private_key": _PRIVATE_KEY_PATTERNS,
    "jwt": _JWT_PATTERNS,
    "generic": _GENERIC_PATTERNS,
    "other": _OTHER_PATTERNS,
}
"""Patterns grouped by category for selective scanning."""
