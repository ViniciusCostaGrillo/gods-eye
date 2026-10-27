"""Correlation Engine generating risk alerts and multi-source investigative inferences."""

from godseye.db.repository import OsintRepository
from godseye.domain.enums import EntityType, RiskLevel
from godseye.domain.models import CorrelationFinding


class CorrelationEngine:
    """Applies correlation rules across deduplicated entities and relationships (Section 4 & 8)."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def evaluate_case(self, case_id: str) -> list[CorrelationFinding]:
        """Run correlation rules on a case and persist new CorrelationFindings."""
        entities = self.repo.list_entities(case_id)
        relationships = self.repo.list_relationships(case_id)
        existing_rule_ids = {f.rule_id for f in self.repo.list_findings(case_id)}
        new_findings: list[CorrelationFinding] = []

        by_type: dict[EntityType, list[str]] = {}
        for ent in entities:
            by_type.setdefault(ent.type, []).append(ent.canonical_value)

        evidence_ids = list({r.evidence_id for r in relationships if r.evidence_id})[:10]

        # Rule 1: Breach Exposure Correlation
        breaches = by_type.get(EntityType.BREACH, [])
        if breaches and "CORR-BREACH-EXPOSURE" not in existing_rule_ids:
            risk = RiskLevel.HIGH if len(breaches) >= 2 else RiskLevel.MEDIUM
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-BREACH-EXPOSURE",
                title=f"Target Exposed in {len(breaches)} Known Breach(es)",
                description=(
                    f"Target or domain appeared in {len(breaches)} breach record(s): "
                    f"{', '.join(breaches[:5])}. Recommend credential rotation and MFA audit."
                ),
                risk=risk,
                confidence=0.90,
                involved_entities=breaches[:5],
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 2: Exposed Network Services & Vulnerabilities (Shodan InternetDB + DNS)
        services = by_type.get(EntityType.EXPOSED_SERVICE, [])
        vulns = by_type.get(EntityType.VULNERABILITY, [])
        if (services or vulns) and "CORR-ATTACK-SURFACE" not in existing_rule_ids:
            risk = RiskLevel.CRITICAL if vulns else RiskLevel.MEDIUM
            desc = f"Discovered {len(services)} exposed network service(s)"
            if vulns:
                desc += f" and {len(vulns)} potential CVE vulnerability indicator(s) ({', '.join(vulns[:5])})"
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-ATTACK-SURFACE",
                title="External Attack Surface & Exposed Services Correlated",
                description=desc + " linked to resolved infrastructure IPs.",
                risk=risk,
                confidence=0.92,
                involved_entities=(services[:4] + vulns[:4]),
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 3: Certificate Transparency Subdomain Footprint
        subdomains = by_type.get(EntityType.SUBDOMAIN, [])
        if subdomains and "CORR-CT-SUBDOMAINS" not in existing_rule_ids:
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-CT-SUBDOMAINS",
                title=f"Passive Certificate Transparency Enumerated {len(subdomains)} Subdomain(s)",
                description=(
                    f"CT logs revealed {len(subdomains)} subdomain(s): {', '.join(subdomains[:5])}. "
                    "Verify that staging/internal hosts are not unintentionally exposed."
                ),
                risk=RiskLevel.LOW,
                confidence=0.95,
                involved_entities=subdomains[:5],
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 4: Cross-Platform Username Leads (Section 5.4: treat as leads, not definitive ID)
        accounts = by_type.get(EntityType.ACCOUNT, [])
        if accounts and "CORR-SOCMINT-LEADS" not in existing_rule_ids:
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-SOCMINT-LEADS",
                title=f"Correlated {len(accounts)} Public Account / Identity Lead(s)",
                description=(
                    f"Found {len(accounts)} public account(s) ({', '.join(accounts[:5])}). "
                    "Per OSINT methodology (Section 5.4), treat username matches as investigative leads "
                    "requiring corroboration, not definitive identification."
                ),
                risk=RiskLevel.INFO,
                confidence=0.75,
                involved_entities=accounts[:5],
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 5: Brazilian Corporate & Compliance Correlation (CNPJ + QSA + Diários + Sanções)
        orgs = by_type.get(EntityType.ORGANIZATION, [])
        persons = by_type.get(EntityType.PERSON, [])
        docs = by_type.get(EntityType.DOCUMENT, [])
        sanctions = by_type.get(EntityType.SANCTION, [])
        if orgs and (persons or docs or sanctions) and "CORR-BR-CORPORATE" not in existing_rule_ids:
            risk = RiskLevel.HIGH if sanctions else RiskLevel.LOW
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-BR-CORPORATE",
                title="Brazilian Corporate QSA, Official Gazettes & Compliance Correlated",
                description=(
                    f"Linked {len(orgs)} organization(s) with {len(persons)} QSA partner(s), "
                    f"{len(docs)} public/compliance document(s), and {len(sanctions)} sanction record(s)."
                ),
                risk=risk,
                confidence=0.94,
                involved_entities=(orgs[:2] + persons[:3] + sanctions[:2]),
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 6: Crypto OSINT & Sanctioned Blockchain Cluster (Expansion Module 4)
        wallets = by_type.get(EntityType.CRYPTO_WALLET, [])
        clusters = by_type.get(EntityType.CRYPTO_CLUSTER, [])
        txs = by_type.get(EntityType.CRYPTO_TRANSACTION, [])
        if (wallets or clusters or txs) and "CORR-CRYPTO-LEDGER" not in existing_rule_ids:
            risk = RiskLevel.CRITICAL if sanctions else RiskLevel.MEDIUM
            desc = (
                f"Correlated {len(wallets)} crypto wallet(s), {len(txs)} ledger transaction(s), "
                f"and {len(clusters)} cluster/counterparty link(s)."
            )
            if sanctions:
                desc += f" ALERT: {len(sanctions)} OFAC/OpenSanctions risk flag(s) detected on wallet!"
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-CRYPTO-LEDGER",
                title="Cryptocurrency On-Chain Activity & Risk Screening Correlated",
                description=desc,
                risk=risk,
                confidence=0.93,
                involved_entities=(wallets[:3] + clusters[:2] + sanctions[:2]),
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        # Rule 7: Phone OSINT & E.164 / Brazilian DDD / ANATEL Correlation (Expansion Module 2)
        phones = by_type.get(EntityType.PHONE, [])
        locations = by_type.get(EntityType.LOCATION, [])
        if phones and "CORR-PHONE-TELECOM" not in existing_rule_ids:
            finding = CorrelationFinding(
                case_id=case_id,
                rule_id="CORR-PHONE-TELECOM",
                title=f"Phone OSINT E.164 & Telecom Metadata Correlated ({len(phones)} Line(s))",
                description=(
                    f"Normalized {len(phones)} phone number(s) ({', '.join(phones[:3])}) "
                    f"with {len(locations)} geographic DDD/state region(s) and telecom line metadata."
                ),
                risk=RiskLevel.INFO,
                confidence=0.91,
                involved_entities=(phones[:3] + locations[:2]),
                evidence_ids=evidence_ids,
            )
            self.repo.save_finding(finding)
            new_findings.append(finding)

        return self.repo.list_findings(case_id)
