"""Tests for Security, RBAC, LGPD Data Minimization & Webhook HMAC Verification."""

import pytest

from godseye.core.security import (
    PermissionDeniedError,
    check_permission,
    compute_content_hash,
    compute_idempotency_key,
    hash_sensitive_identifier,
    mask_cpf,
    mask_plate,
    sanitize_osint_payload,
    sign_webhook_payload,
    verify_webhook_signature,
)
from godseye.domain.enums import Role


def test_rbac_permissions() -> None:
    check_permission(Role.ADMIN, "case:delete")
    check_permission(Role.INVESTIGATOR, "collection:run")
    check_permission(Role.ANALYST, "case:read")
    check_permission(Role.AUDITOR, "audit:read")

    with pytest.raises(PermissionDeniedError):
        check_permission(Role.ANALYST, "collection:run")

    with pytest.raises(PermissionDeniedError):
        check_permission(Role.INVESTIGATOR, "case:delete")


def test_lgpd_minimization_and_payload_sanitization() -> None:
    assert mask_cpf("123.456.789-01") == "***.456.789-**"
    assert mask_plate("BRA2E19") == "BRA-**19"

    h1 = hash_sensitive_identifier("123.456.789-01")
    h2 = hash_sensitive_identifier("12345678901")
    assert h1 == h2

    dirty_payload = {
        "email": "user@example.com",
        "password": "SuperSecretPlaintextPassword123!",
        "cpf": "123.456.789-01",
        "nested": {
            "plaintext_password": "leaked",
            "note": "Found CPF 111.222.333-44 in document",
        },
    }
    clean = sanitize_osint_payload(dirty_payload)
    assert clean["password"] == "[REDACTED_BY_GODSEYE_SECURITY_POLICY]"
    assert clean["nested"]["plaintext_password"] == "[REDACTED_BY_GODSEYE_SECURITY_POLICY]"
    assert clean["cpf"] == "***.456.789-**"
    assert "111.222.333-44" not in clean["nested"]["note"]


def test_provenance_hashes_and_webhook_hmac() -> None:
    c1 = compute_content_hash({"b": 2, "a": 1})
    c2 = compute_content_hash({"a": 1, "b": 2})
    assert c1 == c2

    idem = compute_idempotency_key("case-1", "Example.COM", "rdap", "1.0.0")
    assert len(idem) == 64

    body = b'{"event":"collection.completed"}'
    sig = sign_webhook_payload("topsecret", body)
    assert verify_webhook_signature("topsecret", body, sig) is True
    assert verify_webhook_signature("wrongsecret", body, sig) is False
