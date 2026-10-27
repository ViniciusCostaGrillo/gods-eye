"""Security, RBAC, LGPD/GDPR data minimization, and HMAC webhook verification."""

import hashlib
import hmac
import json
import re
from typing import Any

from godseye.domain.enums import Role

# Forbidden keys that could contain raw credentials or plaintext passwords (Section 1, 5.2, 16)
FORBIDDEN_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "plaintext_password",
        "raw_password",
        "cleartext_password",
        "secret_key",
        "private_key",
        "credential_dump",
        "stealer_log_raw",
    }
)

# Role -> Allowed actions matrix (Section 14.1)
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset(
        {
            "case:create",
            "case:read",
            "case:update",
            "case:delete",
            "target:create",
            "target:read",
            "collection:run",
            "collection:cancel",
            "evidence:read",
            "report:export",
            "source:manage",
            "audit:read",
            "webhook:manage",
            "watchlist:manage",
            "alert:acknowledge",
            "collaboration:write",
            "quality:manage",
            "ai:review",
        }
    ),
    Role.INVESTIGATOR: frozenset(
        {
            "case:create",
            "case:read",
            "case:update",
            "target:create",
            "target:read",
            "collection:run",
            "collection:cancel",
            "evidence:read",
            "report:export",
            "watchlist:manage",
            "alert:acknowledge",
            "collaboration:write",
            "quality:manage",
            "ai:review",
        }
    ),
    Role.ANALYST: frozenset(
        {
            "case:read",
            "case:update",
            "target:read",
            "evidence:read",
            "report:export",
            "alert:acknowledge",
            "collaboration:write",
            "ai:review",
        }
    ),
    Role.AUDITOR: frozenset(
        {
            "case:read",
            "audit:read",
            "report:export",
            "evidence:read",
        }
    ),
}


class PermissionDeniedError(PermissionError):
    """Raised when an actor lacks RBAC permission for an action."""


def check_permission(role: Role | str, action: str) -> None:
    """Verify that the given role has permission to execute `action`."""
    resolved_role = Role(role) if isinstance(role, str) else role
    allowed = ROLE_PERMISSIONS.get(resolved_role, frozenset())
    if action not in allowed:
        raise PermissionDeniedError(
            f"Role '{resolved_role.value}' is not authorized to perform '{action}'"
        )


def compute_content_hash(payload: dict[str, Any] | str) -> str:
    """Compute canonical SHA-256 content hash for provenance & evidence integrity."""
    if isinstance(payload, dict):
        serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    else:
        serialized = str(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_idempotency_key(
    case_id: str,
    target_value: str,
    source_id: str,
    adapter_version: str = "1.0.0",
) -> str:
    """Compute unique idempotency key per Section 13: case_id + target + source + adapter_version."""
    normalized_target = target_value.strip().lower()
    raw = f"{case_id}:{normalized_target}:{source_id}:{adapter_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_sensitive_identifier(value: str, salt: str = "godseye-lgpd-v1") -> str:
    """Hash sensitive identifiers (CPF, Placa, RENAVAM) for LGPD minimization."""
    cleaned = re.sub(r"\W+", "", value.strip().upper())
    return hashlib.sha256(f"{salt}:{cleaned}".encode()).hexdigest()


def mask_cpf(cpf: str) -> str:
    """Mask Brazilian CPF keeping only middle verification digits (LGPD minimization)."""
    digits = re.sub(r"\D", "", cpf)
    if len(digits) == 11:
        return f"***.{digits[3:6]}.{digits[6:9]}-**"
    return "***.***.***-**"


def mask_plate(plate: str) -> str:
    """Mask vehicle license plate (Mercosul / legacy) for LGPD minimization."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", plate.upper())
    if len(cleaned) == 7:
        return f"{cleaned[:3]}-**{cleaned[5:]}"
    return "***-****"


def sanitize_osint_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact plaintext passwords, raw dumps, and full CPFs from payloads."""
    sanitized: dict[str, Any] = {}
    cpf_pattern = re.compile(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b")

    for key, value in payload.items():
        key_lower = key.lower()
        if key_lower in FORBIDDEN_CREDENTIAL_KEYS:
            sanitized[key] = "[REDACTED_BY_GODSEYE_SECURITY_POLICY]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_osint_payload(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_osint_payload(item) if isinstance(item, dict) else item for item in value
            ]
        elif isinstance(value, str) and key_lower in {"cpf", "documento_cpf"}:
            sanitized[key] = mask_cpf(value)
        elif isinstance(value, str) and cpf_pattern.search(value) and key_lower != "cnpj":
            sanitized[key] = cpf_pattern.sub(r"***.\\2.\\3-**", value)
        else:
            sanitized[key] = value
    return sanitized


def sign_webhook_payload(secret: str, payload_bytes: bytes) -> str:
    """Compute HMAC-SHA256 webhook signature header (`sha256=<hex>`)."""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(secret: str, payload_bytes: bytes, signature_header: str) -> bool:
    """Verify webhook signature in constant time (`api-integration` skill)."""
    if not signature_header or not secret:
        return False
    expected = sign_webhook_payload(secret, payload_bytes)
    return hmac.compare_digest(expected, signature_header)
