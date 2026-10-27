"""Domain enumerations for God's Eye OSINT platform."""

from enum import StrEnum


class TargetType(StrEnum):
    """Supported OSINT target types."""

    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    PERSON = "person"
    ORGANIZATION = "organization"
    CNPJ = "cnpj"
    CEP = "cep"
    PROCESSO = "processo"
    VEHICLE_PLATE = "vehicle_plate"
    IMAGE = "image"
    DOCUMENT = "document"


class TrustLevel(StrEnum):
    """Provenance trust level of an OSINT source."""

    OFFICIAL = "official"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(StrEnum):
    """Verification status of a normalized observation."""

    VERIFIED = "verified"
    CORROBORATED = "corroborated"
    UNVERIFIED_LEAD = "unverified_lead"
    INFERRED = "inferred"


class Role(StrEnum):
    """RBAC roles as defined in Section 14.1 of backend documentation."""

    ADMIN = "admin"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class CaseStatus(StrEnum):
    """Lifecycle status of an investigation case."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ARCHIVED = "archived"
    CLOSED = "closed"


class LegalBasis(StrEnum):
    """LGPD / GDPR legal basis for OSINT collection."""

    CYBERSECURITY_DEFENSE = "legitimate_interest_cybersecurity"
    FRAUD_PREVENTION = "fraud_prevention_and_security"
    REGULATORY_COMPLIANCE = "legal_or_regulatory_obligation"
    JUDICIAL_PROCESS = "regular_exercise_of_rights_in_process"
    CONSENT = "explicit_subject_consent"
    PUBLIC_ADMINISTRATION = "public_policy_transparency"


class JobStatus(StrEnum):
    """Status of an asynchronous collection job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CACHED = "cached"


class RiskLevel(StrEnum):
    """Risk classification for targets and correlation alerts."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityType(StrEnum):
    """Base entity types in the investigative graph (Section 6.1)."""

    PERSON = "Person"
    ACCOUNT = "Account"
    EMAIL = "Email"
    PHONE = "Phone"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    IP_ADDRESS = "IPAddress"
    ASN = "ASN"
    ORGANIZATION = "Organization"
    CERTIFICATE = "Certificate"
    EXPOSED_SERVICE = "ExposedService"
    VULNERABILITY = "Vulnerability"
    BREACH = "Breach"
    DOCUMENT = "Document"
    IMAGE = "Image"
    LOCATION = "Location"
    SANCTION = "Sanction"
    LEGAL_CASE = "LegalCase"
    VEHICLE = "Vehicle"
    MALWARE_IOC = "MalwareIOC"
    WEB_SNAPSHOT = "WebSnapshot"


class RelationType(StrEnum):
    """Standardized investigative relationships (Section 6.2 & Section 13 Brazil)."""

    USES = "uses"
    OWNS = "owns"
    APPEARS_IN = "appears_in"
    RESOLVES_TO = "resolves_to"
    ISSUED_FOR = "issued_for"
    HAS_CERTIFICATE = "has_certificate"
    HAS_SUBDOMAIN = "has_subdomain"
    EXPOSES_SERVICE = "exposes_service"
    HAS_VULNERABILITY = "has_vulnerability"
    ASSOCIATED_WITH = "associated_with"
    MENTIONED_IN = "mentioned_in"
    LOCATED_AT = "located_at"
    HAS_QSA = "has_qsa"
    HAS_CASE = "has_case"
    HAS_SANCTION = "has_sanction"
    HAS_CONTRACT = "has_contract"
    IS_PEP = "is_pep"
    HOSTED_IN_ASN = "hosted_in_asn"
    ARCHIVED_AT = "archived_at"
    FLAGGED_AS = "flagged_as"


class EventType(StrEnum):
    """Event types for the event-driven pipeline (Section 9)."""

    TARGET_CREATED = "target.created"
    COLLECTION_REQUESTED = "collection.requested"
    COLLECTION_COMPLETED = "collection.completed"
    COLLECTION_FAILED = "collection.failed"
    OBSERVATION_NORMALIZED = "observation.normalized"
    ENTITY_CREATED = "entity.created"
    ENTITY_MERGED = "entity.merged"
    RELATIONSHIP_CREATED = "relationship.created"
    CORRELATION_MATCHED = "correlation.matched"
    CASE_REPORT_REQUESTED = "case.report.requested"
