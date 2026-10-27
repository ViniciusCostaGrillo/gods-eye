"""Domain enumerations for God's Eye OSINT platform (Core + Phase 2 Expansion)."""

from enum import StrEnum


class TargetType(StrEnum):
    """Supported OSINT target types (Core + Phone, Crypto, Media)."""

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
    CRYPTO_ADDRESS = "crypto_address"
    IMAGE = "image"
    DOCUMENT = "document"


class TrustLevel(StrEnum):
    """Provenance trust level of an OSINT source (Section 8.2)."""

    OFFICIAL = "official"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(StrEnum):
    """Verification status of an observation, entity, or relationship (Section 7.1)."""

    VERIFIED = "verified"
    CORROBORATED = "corroborated"
    UNVERIFIED_LEAD = "unverified_lead"
    INFERRED = "inferred"
    CONTESTED = "contested"
    FALSE_POSITIVE = "false_positive"


class SourceReviewStatus(StrEnum):
    """Lifecycle status of a source in the dynamic catalog (Section 4.3)."""

    ACTIVE = "active"
    CANDIDATE = "candidate"
    DEPRECATED = "deprecated"


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
    """Risk classification for targets, watchlists, and correlation alerts."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityType(StrEnum):
    """Base entity types in the investigative graph (Core + Expansion)."""

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
    CRYPTO_WALLET = "CryptoWallet"
    CRYPTO_TRANSACTION = "CryptoTransaction"
    CRYPTO_CLUSTER = "CryptoCluster"
    PASTE_EXPOSURE = "PasteExposure"


class RelationType(StrEnum):
    """Standardized investigative relationships (Core + Expansion)."""

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
    TRANSACTED_WITH = "transacted_with"
    BELONGS_TO_CLUSTER = "belongs_to_cluster"
    REGISTERED_CARRIER = "registered_carrier"


class EventType(StrEnum):
    """Event types for the event-driven pipeline and Watchlist alerts (Section 9 & Exp Section 2.3)."""

    TARGET_CREATED = "target.created"
    COLLECTION_REQUESTED = "collection.requested"
    COLLECTION_COMPLETED = "collection.completed"
    COLLECTION_FAILED = "collection.failed"
    OBSERVATION_NORMALIZED = "observation.normalized"
    ENTITY_CREATED = "entity.created"
    ENTITY_UPDATED = "entity.updated"
    ENTITY_MERGED = "entity.merged"
    RELATIONSHIP_CREATED = "relationship.created"
    CORRELATION_MATCHED = "correlation.matched"
    CASE_REPORT_REQUESTED = "case.report.requested"
    BREACH_DETECTED = "breach.detected"
    SANCTION_DETECTED = "sanction.detected"
    LEGAL_CASE_CREATED = "legal_case.created"
    LEGAL_CASE_UPDATED = "legal_case.updated"
    DOMAIN_CERTIFICATE_ISSUED = "domain.certificate_issued"
    DOMAIN_SUBDOMAIN_DISCOVERED = "domain.subdomain_discovered"
    CRYPTO_ADDRESS_FLAGGED = "crypto.address_flagged"
    NEWS_MENTION_DETECTED = "news.mention_detected"
    OFFICIAL_GAZETTE_MENTION_DETECTED = "official_gazette.mention_detected"
