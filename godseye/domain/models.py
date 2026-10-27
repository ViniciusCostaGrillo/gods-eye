"""Domain models for God's Eye OSINT platform (Core + Phase 2 Expansion)."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from godseye.domain.enums import (
    CaseStatus,
    EntityType,
    JobStatus,
    LegalBasis,
    RelationType,
    RiskLevel,
    SourceReviewStatus,
    TargetType,
    TrustLevel,
    VerificationStatus,
)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).isoformat()


def new_id() -> str:
    """Generate a unique string UUID4."""
    return str(uuid4())


class Case(BaseModel):
    """Investigative case grouping OSINT targets, evidence, and audit trail."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    title: str = Field(..., min_length=3, max_length=200)
    owner: str = Field(default="sec-analyst")
    status: CaseStatus = Field(default=CaseStatus.OPEN)
    legal_basis: LegalBasis = Field(default=LegalBasis.CYBERSECURITY_DEFENSE)
    purpose: str = Field(
        default="Authorized defensive cybersecurity threat intelligence & asset reconnaissance"
    )
    notes: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)
    closed_at: str | None = Field(default=None)


class Target(BaseModel):
    """Investigative target attached to a Case."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    type: TargetType
    value: str
    normalized_value: str
    risk: RiskLevel = Field(default=RiskLevel.INFO)
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)


class SourceMetadata(BaseModel):
    """Catalog metadata for an OSINT source / adapter (Core + Section 4.4 OSINT Brazuca)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    provider: str
    category: str
    url: str
    description: str
    trust_level: TrustLevel = Field(default=TrustLevel.HIGH)
    tos_url: str = Field(default="")
    documentation_url: str = Field(default="")
    auth_type: str = Field(default="none")
    rate_limit_per_min: int = Field(default=30)
    cost_per_call: float = Field(default=0.0)
    region: str = Field(default="global")
    accepts: list[TargetType] = Field(default_factory=list)
    produces: list[EntityType] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    has_live_adapter: bool = Field(default=False)
    status: SourceReviewStatus = Field(default=SourceReviewStatus.ACTIVE)
    last_reviewed_at: str | None = Field(default_factory=utc_now_iso)


class CollectionJob(BaseModel):
    """Execution job for a specific target and OSINT source."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    target_id: str
    source_id: str
    status: JobStatus = Field(default=JobStatus.PENDING)
    priority: int = Field(default=5, ge=1, le=10)
    idempotency_key: str = Field(default="")
    requested_at: str = Field(default_factory=utc_now_iso)
    started_at: str | None = Field(default=None)
    finished_at: str | None = Field(default=None)
    error: str | None = Field(default=None)
    cost: float = Field(default=0.0)
    duration_ms: float = Field(default=0.0)


class RawObservation(BaseModel):
    """Observation emitted by a Collector adapter (Section 7.1 mandatory metadata)."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    source_name: str
    source_url: str | None = None
    retrieved_at: str = Field(default_factory=utc_now_iso)
    adapter_version: str = Field(default="1.0.0")
    entity_type: EntityType
    entity_value: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    verification_status: VerificationStatus = Field(default=VerificationStatus.UNVERIFIED_LEAD)
    legal_basis: LegalBasis = Field(default=LegalBasis.CYBERSECURITY_DEFENSE)
    retention_policy: str = Field(default="90d")
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = Field(default="")
    related_to_value: str | None = Field(default=None)
    related_to_type: EntityType | None = Field(default=None)
    relation: RelationType = Field(default=RelationType.ASSOCIATED_WITH)
    tags: list[str] = Field(default_factory=list)


class RawEvidence(BaseModel):
    """Immutable evidence record stored before normalization (Section 6)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    job_id: str
    source_id: str
    source_name: str
    url: str | None = None
    retrieved_at: str = Field(default_factory=utc_now_iso)
    adapter_version: str = Field(default="1.0.0")
    content_hash: str
    raw_payload: dict[str, Any]
    legal_basis: LegalBasis = Field(default=LegalBasis.CYBERSECURITY_DEFENSE)
    retention_expires_at: str


class NormalizedObservation(BaseModel):
    """Standardized observation linked to RawEvidence."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    evidence_id: str
    source_id: str
    entity_type: EntityType
    entity_value: str
    canonical_value: str
    observed_at: str = Field(default_factory=utc_now_iso)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    verification: VerificationStatus = Field(default=VerificationStatus.UNVERIFIED_LEAD)
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    related_to_value: str | None = None
    related_to_type: EntityType | None = None
    relation: RelationType = Field(default=RelationType.ASSOCIATED_WITH)


class Entity(BaseModel):
    """Deduplicated canonical entity in the investigative graph."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    type: EntityType
    canonical_value: str
    aliases: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)


class EntityRelationship(BaseModel):
    """Directed edge between two entities backed by evidence."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    from_entity_id: str
    to_entity_id: str
    from_label: str = Field(default="")
    to_label: str = Field(default="")
    relation: RelationType
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_id: str
    source_id: str
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)


class CorrelationFinding(BaseModel):
    """Inference or risk alert generated by the Correlation Engine."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    rule_id: str
    title: str
    description: str
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    involved_entities: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)


class AuditEvent(BaseModel):
    """Immutable compliance and security audit log entry (Section 14.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    actor_id: str
    actor_role: str = Field(default="investigator")
    case_id: str | None = None
    action: str
    object_id: str | None = None
    ip: str = Field(default="127.0.0.1")
    user_agent: str = Field(default="GodsEye-CLI/1.0")
    timestamp: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WebhookSubscription(BaseModel):
    """Webhook registration for event-driven notifications (api-integration skill)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    subscriber_url: str
    events: list[str] = Field(default_factory=list)
    secret: str = Field(default="")
    active: bool = Field(default=True)
    created_at: str = Field(default_factory=utc_now_iso)


# --- Brazilian Specialized OSINT Models (Section 11 of apis-osint-brasil.md) ---


class BrazilianCompany(BaseModel):
    """Brazilian corporate registration model (CNPJ / QSA)."""

    model_config = ConfigDict(extra="forbid")

    cnpj: str
    razao_social: str
    nome_fantasia: str | None = None
    situacao_cadastral: str = "ATIVA"
    data_abertura: str | None = None
    cnae_principal: str | None = None
    cnaes_secundarios: list[str] = Field(default_factory=list)
    endereco: str | None = None
    municipio: str | None = None
    uf: str | None = None
    cep: str | None = None
    capital_social: float = 0.0
    natureza_juridica: str | None = None
    qsa: list[dict[str, Any]] = Field(default_factory=list)


class BrazilianPerson(BaseModel):
    """Privacy-minimized Brazilian person record (LGPD compliant: hashed CPF)."""

    model_config = ConfigDict(extra="forbid")

    nome: str
    cpf_hash: str
    cpf_masked: str = "***"
    data_nascimento_faixa: str | None = None
    municipio: str | None = None
    uf: str | None = None
    pep_flag: bool = False
    sanctions: list[str] = Field(default_factory=list)


class LegalCase(BaseModel):
    """Brazilian judicial process metadata (DataJud / CNJ)."""

    model_config = ConfigDict(extra="forbid")

    numero_processo: str
    tribunal: str
    classe: str
    assunto: str
    orgao: str | None = None
    partes: list[str] = Field(default_factory=list)
    movimentacoes: list[str] = Field(default_factory=list)
    valor_causa: float | None = None
    status: str = "EM_ANDAMENTO"


class Vehicle(BaseModel):
    """Privacy-minimized Brazilian vehicle record (Senatran / SERPRO compliant)."""

    model_config = ConfigDict(extra="forbid")

    placa_hash: str
    placa_masked: str
    renavam_hash: str | None = None
    chassi_hash: str | None = None
    marca: str | None = None
    modelo: str | None = None
    ano_fabricacao: int | None = None
    ano_modelo: int | None = None
    cor: str | None = None
    combustivel: str | None = None
    situacao: str = "REGULAR"
    restricoes: list[str] = Field(default_factory=list)
    leiloes: list[str] = Field(default_factory=list)
    sinistros: list[str] = Field(default_factory=list)


class OfficialPublication(BaseModel):
    """Brazilian official gazette publication (DOU / Querido Diário)."""

    model_config = ConfigDict(extra="forbid")

    diario: str
    data_publicacao: str
    caderno: str | None = None
    pagina: str | None = None
    texto: str
    url_original: str | None = None
    entidade_mencionada: str


class Sanction(BaseModel):
    """Compliance sanction record (CEIS / CNEP / CEAF / CEPIM / OpenSanctions)."""

    model_config = ConfigDict(extra="forbid")

    tipo: str
    orgao_sancionador: str
    numero_processo: str | None = None
    data_inicio: str | None = None
    data_fim: str | None = None
    fundamento_legal: str | None = None
    entidade_sancionada: str


# ============================================================================
# Phase 2 Expansion Models (expansao-osint-modulos-fontes-apis.md)
# ============================================================================


# --- Section 2: Watchlists & Alerts ---


class AlertRule(BaseModel):
    """Condition and threshold rule attached to a Watchlist (Section 2.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    watchlist_id: str = Field(default="")
    event_type: str = Field(default="entity.created")
    condition: str = Field(default="contains")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: RiskLevel = Field(default=RiskLevel.HIGH)
    cooldown_minutes: int = Field(default=15, ge=0)
    enabled: bool = Field(default=True)


class Watchlist(BaseModel):
    """Continuous monitoring entry for an entity or target value (Section 2.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    entity_id: str | None = None
    type: TargetType
    value: str
    alert_rules: list[AlertRule] = Field(default_factory=list)
    frequency: str = Field(default="realtime")  # realtime, hourly, daily
    channels: list[str] = Field(default_factory=lambda: ["cli", "webhook"])
    owner: str = Field(default="sec-analyst")
    active: bool = Field(default=True)
    created_at: str = Field(default_factory=utc_now_iso)


class Alert(BaseModel):
    """Triggered alert when a Watchlist target matches an OSINT event (Section 2.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    watchlist_id: str
    case_id: str = Field(default="")
    triggered_at: str = Field(default_factory=utc_now_iso)
    source_id: str
    evidence_id: str | None = None
    severity: RiskLevel = Field(default=RiskLevel.HIGH)
    message: str
    acknowledged_by: str | None = None
    acknowledged_at: str | None = None


# --- Section 3: Phone OSINT ---


class PhoneRecord(BaseModel):
    """First-class Phone OSINT record with E.164, DDD, carrier, and line type (Section 3.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    e164: str
    national_format: str
    country: str
    area_code: str
    carrier_original: str
    carrier_current: str
    line_type: str  # mobile, landline, voip, toll_free, unknown
    portability_status: str = "UNKNOWN"
    risk_score: float = Field(default=0.1, ge=0.0, le=1.0)
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)


class PhoneObservation(BaseModel):
    """Provenance record for a phone observation (Section 3.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    phone_id: str
    source_id: str
    observed_at: str = Field(default_factory=utc_now_iso)
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    adapter_version: str = Field(default="1.0.0")


class PhoneRelationship(BaseModel):
    """Link between a PhoneRecord and another investigative entity (Section 3.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    phone_id: str
    related_entity_id: str
    relation: RelationType = Field(default=RelationType.ASSOCIATED_WITH)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_id: str


# --- Section 5: Crypto OSINT ---


class CryptoWallet(BaseModel):
    """Cryptocurrency wallet metadata and risk assessment (Section 5.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    address: str
    blockchain: str  # bitcoin, ethereum, solana, tron, bsc, polygon
    label: str = "unattributed_wallet"
    balance: float = 0.0
    tx_count: int = 0
    risk_score: float = Field(default=0.1, ge=0.0, le=1.0)
    sanctioned: bool = False
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)


class CryptoTransaction(BaseModel):
    """On-chain transaction record between addresses (Section 5.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    blockchain: str
    tx_hash: str
    from_address: str
    to_address: str
    value: float
    token: str = "NATIVE"
    timestamp: str = Field(default_factory=utc_now_iso)
    block: int | None = None
    source_id: str = "crypto_osint"


class CryptoCluster(BaseModel):
    """Cluster of co-spent or attributed cryptocurrency addresses (Section 5.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    label: str
    addresses: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    source_id: str = "crypto_osint"
    attribution: str = "heuristic_cluster"
    evidence_id: str = ""


# --- Section 7: Investigative Collaboration ---


class CaseComment(BaseModel):
    """Analyst comment on a case, entity, or evidence item with @mentions (Section 7.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    entity_id: str | None = None
    evidence_id: str | None = None
    author_id: str = Field(default="sec-analyst")
    body: str
    mentions: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)
    edited_at: str | None = None


class InvestigativeTask(BaseModel):
    """Collaborative task assigned to an analyst within a Case (Section 7.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    title: str
    description: str = ""
    assignee_id: str = Field(default="sec-analyst")
    status: str = Field(default="open")  # open, in_progress, done
    due_date: str | None = None
    created_by: str = Field(default="sec-analyst")
    created_at: str = Field(default_factory=utc_now_iso)


class VerificationRecord(BaseModel):
    """Human review / verification decision on an entity or relationship (Section 7.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    entity_id: str | None = None
    relationship_id: str | None = None
    status: VerificationStatus
    reviewer_id: str = Field(default="sec-analyst")
    reason: str
    evidence_id: str | None = None
    reviewed_at: str = Field(default_factory=utc_now_iso)


class CaseVersion(BaseModel):
    """Immutable versioned snapshot of an investigative dossier (Section 7.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    version: int = Field(ge=1)
    snapshot_url: str = ""
    snapshot_hash: str = ""
    created_by: str = Field(default="sec-analyst")
    created_at: str = Field(default_factory=utc_now_iso)
    change_summary: str


# --- Section 8: Data Quality & Governance ---


class DataQualityScore(BaseModel):
    """Multi-factor reliability score for an observation or relationship (Section 8.1 & 8.4)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    observation_id: str | None = None
    relationship_id: str | None = None
    source_trust: float = Field(ge=0.0, le=1.0)
    recency: float = Field(ge=0.0, le=1.0)
    corroboration_count: int = Field(default=1, ge=1)
    official_source_bonus: float = Field(default=0.0, ge=0.0, le=0.3)
    conflict_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    stale_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=1.0)
    explanation: str = ""
    calculated_at: str = Field(default_factory=utc_now_iso)


class DataConflict(BaseModel):
    """Detected contradiction between two observations on the same entity (Section 8.4)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    entity_id: str
    observation_a_id: str
    observation_b_id: str
    conflict_type: str
    description: str = ""
    status: str = Field(default="open")  # open, resolved, dismissed
    resolved_by: str | None = None
    resolved_at: str | None = None


# --- Section 9: Assistive AI with Mandatory Human Review ---


class AIInference(BaseModel):
    """Auditable assistive AI output explicitly marked `model_generated` (Section 9.3)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    case_id: str
    input_evidence_ids: list[str] = Field(default_factory=list)
    model: str = Field(default="godseye-assistive-synthesizer")
    model_version: str = Field(default="1.0.0")
    prompt_hash: str
    task_type: str = Field(default="dossier_summary")
    output: str
    confidence_kind: str = Field(default="model_generated")
    human_review_status: str = Field(default="pending_review")  # pending_review, approved, rejected
    created_at: str = Field(default_factory=utc_now_iso)
    reviewed_by: str | None = None
    reviewed_at: str | None = None
