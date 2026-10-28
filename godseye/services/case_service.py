"""Case & Target Management Service with RBAC, Target Auto-Detection (Phone/Crypto/BR) & Audit Logging."""

import ipaddress
import re
from typing import Any

from godseye.collectors.expansion_sources import parse_e164_phone
from godseye.core.security import (
    check_permission,
    hash_sensitive_identifier,
    mask_plate,
)
from godseye.db.repository import OsintRepository
from godseye.domain.enums import (
    CaseStatus,
    EntityType,
    LegalBasis,
    Role,
    TargetType,
    VerificationStatus,
)
from godseye.domain.models import AuditEvent, Case, Entity, Target

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CNPJ_RE = re.compile(r"^\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}$")
CEP_RE = re.compile(r"^\d{5}-\d{3}$")
CNJ_PROCESSO_RE = re.compile(r"^\d{7}-?\d{2}\.?\d{4}\.?\d\.?\d{2}\.?\d{4}$")
BR_PLATE_RE = re.compile(r"^[A-Z]{3}-?[0-9][A-Z0-9][0-9]{2}$", re.IGNORECASE)
ETH_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
BTC_ADDR_RE = re.compile(r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}$")
TRON_ADDR_RE = re.compile(r"^T[a-zA-HJ-NP-Z0-9]{33}$")
PHONE_INTL_RE = re.compile(r"^\+\d{10,15}$")
PHONE_BR_FMT_RE = re.compile(r"^\(?\d{2}\)?\s*9?\d{4}-?\d{4}$")
IMAGE_EXT_RE = re.compile(r".+\.(?:png|jpg|jpeg|webp|gif|tiff|bmp)$", re.IGNORECASE)
CPF_RE = re.compile(r"^\d{3}\.\d{3}\.\d{3}-\d{2}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_target_type(raw_value: str) -> TargetType:
    """Automatically detect TargetType from a raw string input."""
    val = raw_value.strip()
    if EMAIL_RE.match(val):
        return TargetType.EMAIL

    try:
        ipaddress.ip_address(val)
        return TargetType.IP
    except ValueError:
        pass

    if ETH_ADDR_RE.match(val) or BTC_ADDR_RE.match(val) or TRON_ADDR_RE.match(val):
        return TargetType.CRYPTO_ADDRESS

    if IMAGE_EXT_RE.match(val):
        return TargetType.IMAGE

    if CPF_RE.match(val):
        return TargetType.PERSON

    if PHONE_INTL_RE.match(re.sub(r"[\s()-]", "", val)) or (
        PHONE_BR_FMT_RE.match(val) and ("(" in val or "-" in val or " " in val or val.startswith("+"))
    ):
        return TargetType.PHONE

    digits = re.sub(r"\D", "", val)
    if CNPJ_RE.match(val) or (len(digits) == 14 and digits.isdigit()):
        return TargetType.CNPJ
    if CNJ_PROCESSO_RE.match(val) or (len(digits) == 20 and digits.isdigit()):
        return TargetType.PROCESSO
    if CEP_RE.match(val) or (len(digits) == 8 and digits.isdigit()):
        return TargetType.CEP
    if len(digits) in (10, 11, 12, 13) and digits.isdigit() and len(val.replace(" ", "").replace("-", "")) <= 15:
        return TargetType.PHONE
    if BR_PLATE_RE.match(val):
        return TargetType.VEHICLE_PLATE
    if DOMAIN_RE.match(val.lower()):
        return TargetType.DOMAIN
    # Multi-word alphabetic string (e.g. "Linus Torvalds", "Vinicius Costa") -> Person
    words = [w for w in val.split() if any(ch.isalpha() for ch in w)]
    if " " in val and len(words) >= 2:
        return TargetType.PERSON
    return TargetType.USERNAME


def normalize_target_value(target_type: TargetType, raw_value: str) -> str:
    """Normalize target value according to its type and LGPD minimization rules."""
    val = raw_value.strip()
    match target_type:
        case TargetType.EMAIL | TargetType.DOMAIN:
            return val.lower()
        case TargetType.CNPJ | TargetType.CEP | TargetType.PROCESSO:
            return re.sub(r"\D", "", val)
        case TargetType.PHONE:
            return str(parse_e164_phone(val)["e164"])
        case TargetType.CRYPTO_ADDRESS:
            return val.lower() if val.startswith("0x") else val
        case TargetType.VEHICLE_PLATE:
            return f"{mask_plate(val)}#{hash_sensitive_identifier(val)[:10]}"
        case TargetType.USERNAME:
            return val.lstrip("@").strip()
        case _:
            return val


def target_type_to_entity_type(target_type: TargetType) -> EntityType:
    """Map TargetType to canonical graph EntityType."""
    mapping: dict[TargetType, EntityType] = {
        TargetType.EMAIL: EntityType.EMAIL,
        TargetType.DOMAIN: EntityType.DOMAIN,
        TargetType.IP: EntityType.IP_ADDRESS,
        TargetType.USERNAME: EntityType.ACCOUNT,
        TargetType.CNPJ: EntityType.ORGANIZATION,
        TargetType.ORGANIZATION: EntityType.ORGANIZATION,
        TargetType.PERSON: EntityType.PERSON,
        TargetType.CEP: EntityType.LOCATION,
        TargetType.PROCESSO: EntityType.LEGAL_CASE,
        TargetType.VEHICLE_PLATE: EntityType.VEHICLE,
        TargetType.PHONE: EntityType.PHONE,
        TargetType.CRYPTO_ADDRESS: EntityType.CRYPTO_WALLET,
        TargetType.IMAGE: EntityType.IMAGE,
        TargetType.DOCUMENT: EntityType.DOCUMENT,
    }
    return mapping.get(target_type, EntityType.DOCUMENT)


class CaseService:
    """Manages investigative cases, targets, RBAC authorization, and audit logs."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def create_case(
        self,
        title: str,
        owner: str = "sec-analyst",
        legal_basis: LegalBasis = LegalBasis.CYBERSECURITY_DEFENSE,
        purpose: str = "Authorized cybersecurity threat intelligence & OSINT investigation",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> Case:
        """Create a new investigative case with mandatory legal basis and audit event."""
        check_permission(actor_role, "case:create")
        case = Case(
            title=title,
            owner=owner,
            legal_basis=legal_basis,
            purpose=purpose,
        )
        self.repo.save_case(case)
        self.repo.record_audit(
            AuditEvent(
                actor_id=owner,
                actor_role=actor_role.value,
                case_id=case.id,
                action="case.created",
                object_id=case.id,
                metadata={"title": title, "legal_basis": legal_basis.value, "purpose": purpose},
            )
        )
        return case

    def get_case(self, case_id: str, actor_role: Role = Role.ANALYST) -> Case | None:
        """Retrieve a case by ID."""
        check_permission(actor_role, "case:read")
        return self.repo.get_case(case_id)

    def list_cases(self, actor_role: Role = Role.ANALYST) -> list[Case]:
        """List all cases."""
        check_permission(actor_role, "case:read")
        return self.repo.list_cases()

    def update_case(
        self,
        case_id: str,
        status: CaseStatus | None = None,
        note: str | None = None,
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> Case | None:
        """Update case status or append an analyst note."""
        check_permission(actor_role, "case:update")
        case = self.repo.get_case(case_id)
        if case is None:
            return None
        if status is not None:
            case.status = status
        if note:
            case.notes.append(note)
        self.repo.save_case(case)
        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=case.id,
                action="case.updated",
                object_id=case.id,
                metadata={"status": case.status.value, "notes_count": len(case.notes)},
            )
        )
        return case

    def delete_case(
        self,
        case_id: str,
        actor_id: str = "admin",
        actor_role: Role = Role.ADMIN,
    ) -> bool:
        """Delete a case and its associated data (requires ADMIN role)."""
        check_permission(actor_role, "case:delete")
        deleted = self.repo.delete_case(case_id)
        if deleted:
            self.repo.record_audit(
                AuditEvent(
                    actor_id=actor_id,
                    actor_role=actor_role.value,
                    case_id=case_id,
                    action="case.deleted",
                    object_id=case_id,
                )
            )
        return deleted

    def add_target(
        self,
        case_id: str,
        value: str,
        target_type: TargetType | None = None,
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.INVESTIGATOR,
    ) -> Target:
        """Validate, normalize, and attach a target to a Case, creating its root graph Entity."""
        check_permission(actor_role, "target:create")
        resolved_type = target_type or detect_target_type(value)
        normalized = normalize_target_value(resolved_type, value)

        for existing in self.repo.list_targets(case_id):
            if existing.type == resolved_type and existing.normalized_value == normalized:
                return existing

        target = Target(
            case_id=case_id,
            type=resolved_type,
            value=value.strip(),
            normalized_value=normalized,
        )
        self.repo.save_target(target)

        root_entity_type = target_type_to_entity_type(resolved_type)
        existing_ent = self.repo.find_entity(case_id, root_entity_type, normalized)
        if existing_ent is None:
            self.repo.save_entity(
                Entity(
                    case_id=case_id,
                    type=root_entity_type,
                    canonical_value=normalized,
                    aliases=[value.strip()] if value.strip() != normalized else [],
                    attributes={"is_root_target": True, "verification": VerificationStatus.VERIFIED.value},
                    confidence=1.0,
                    sources=["analyst_input"],
                )
            )

        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="target.added",
                object_id=target.id,
                metadata={"type": resolved_type.value, "normalized_value": normalized},
            )
        )
        return target

    def list_audit_log(
        self,
        case_id: str | None = None,
        actor_role: Role = Role.AUDITOR,
    ) -> list[dict[str, Any]]:
        """Return audit trail entries (accessible to AUDITOR and ADMIN)."""
        check_permission(actor_role, "audit:read")
        return [e.model_dump() for e in self.repo.list_audit_events(case_id=case_id)]
