"""Reporting, Timeline, Graph Visualization (ASCII/Mermaid/JSON) & Dossier Export Service."""

import csv
import io
import json
from typing import Any

from godseye.core.security import check_permission
from godseye.db.repository import OsintRepository
from godseye.domain.enums import Role
from godseye.domain.models import AuditEvent, utc_now_iso


class ReportingService:
    """Generates auditable OSINT dossiers, timelines, graphs, and exports (Section 4 & 10.5)."""

    def __init__(self, repo: OsintRepository) -> None:
        self.repo = repo

    def get_graph(self, case_id: str, actor_role: Role = Role.ANALYST) -> dict[str, Any]:
        """Return investigative graph nodes, edges, ASCII rendering, and Mermaid diagram."""
        check_permission(actor_role, "evidence:read")
        entities = self.repo.list_entities(case_id)
        relationships = self.repo.list_relationships(case_id)

        nodes = [
            {
                "id": e.id,
                "type": e.type.value,
                "label": e.canonical_value,
                "confidence": e.confidence,
                "sources": e.sources,
                "attributes": e.attributes,
            }
            for e in entities
        ]
        edges = [
            {
                "id": r.id,
                "source": r.from_entity_id,
                "target": r.to_entity_id,
                "from_label": r.from_label,
                "to_label": r.to_label,
                "relation": r.relation.value,
                "confidence": r.confidence,
                "source_id": r.source_id,
                "evidence_id": r.evidence_id,
            }
            for r in relationships
        ]

        # Build Mermaid flowchart
        mermaid_lines = ["flowchart LR"]
        for r in relationships:
            src_safe = r.from_label.replace('"', "'")
            dst_safe = r.to_label.replace('"', "'")
            mermaid_lines.append(
                f'    n_{r.from_entity_id[:8]}["{src_safe}"] -->|"{r.relation.value}"| n_{r.to_entity_id[:8]}["{dst_safe}"]'
            )

        # Build ASCII relationship list
        ascii_lines = [
            f"  [{r.source_id}] {r.from_label}  --({r.relation.value} | conf={r.confidence:.2f})-->  {r.to_label}"
            for r in relationships
        ]

        return {
            "case_id": case_id,
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "mermaid": "\n".join(mermaid_lines),
            "ascii_graph": "\n".join(ascii_lines) if ascii_lines else "  (No graph edges recorded yet)",
        }

    def get_timeline(self, case_id: str, actor_role: Role = Role.ANALYST) -> list[dict[str, Any]]:
        """Build chronological timeline of targets, jobs, evidence, and correlation findings."""
        check_permission(actor_role, "evidence:read")
        events: list[dict[str, Any]] = []

        case = self.repo.get_case(case_id)
        if case:
            events.append(
                {
                    "timestamp": case.created_at,
                    "event_type": "CASE_CREATED",
                    "summary": f"Case '{case.title}' opened under legal basis '{case.legal_basis.value}'",
                    "source": case.owner,
                }
            )

        for t in self.repo.list_targets(case_id):
            events.append(
                {
                    "timestamp": t.first_seen,
                    "event_type": "TARGET_ADDED",
                    "summary": f"Target [{t.type.value}] '{t.normalized_value}' registered",
                    "source": "analyst",
                }
            )

        for ev in self.repo.list_evidence(case_id):
            events.append(
                {
                    "timestamp": ev.retrieved_at,
                    "event_type": "EVIDENCE_COLLECTED",
                    "summary": f"Evidence collected from {ev.source_name} (sha256={ev.content_hash[:12]}...)",
                    "source": ev.source_id,
                }
            )

        for f in self.repo.list_findings(case_id):
            events.append(
                {
                    "timestamp": f.created_at,
                    "event_type": f"CORRELATION_{f.risk.value.upper()}",
                    "summary": f"[{f.rule_id}] {f.title}: {f.description}",
                    "source": "correlation_engine",
                }
            )

        events.sort(key=lambda item: str(item["timestamp"]))
        return events

    def generate_dossier(
        self,
        case_id: str,
        export_format: str = "json",
        actor_id: str = "sec-analyst",
        actor_role: Role = Role.ANALYST,
    ) -> dict[str, Any]:
        """Generate a complete auditable OSINT dossier in JSON, Markdown, or CSV format."""
        check_permission(actor_role, "report:export")
        case = self.repo.get_case(case_id)
        if case is None:
            raise ValueError(f"Case '{case_id}' not found")

        targets = [t.model_dump() for t in self.repo.list_targets(case_id)]
        jobs = [j.model_dump() for j in self.repo.list_jobs(case_id)]
        evidence = [e.model_dump() for e in self.repo.list_evidence(case_id)]
        entities = [ent.model_dump() for ent in self.repo.list_entities(case_id)]
        findings = [f.model_dump() for f in self.repo.list_findings(case_id)]
        graph = self.get_graph(case_id, actor_role=actor_role)
        timeline = self.get_timeline(case_id, actor_role=actor_role)

        dossier: dict[str, Any] = {
            "report_metadata": {
                "generator": "God's Eye (𓂀) OSINT Platform v1.0.0",
                "generated_at": utc_now_iso(),
                "generated_by": actor_id,
                "lgpd_compliance_notice": (
                    "All evidence includes provenance, SHA-256 integrity hashes, and PII minimization. "
                    "Plaintext credentials and unauthorized dumps are strictly prohibited."
                ),
            },
            "case": case.model_dump(),
            "summary": {
                "targets_count": len(targets),
                "jobs_count": len(jobs),
                "evidence_count": len(evidence),
                "entities_count": len(entities),
                "relationships_count": graph["edges_count"],
                "findings_count": len(findings),
            },
            "targets": targets,
            "findings": findings,
            "entities": entities,
            "graph": graph,
            "timeline": timeline,
            "evidence": evidence,
        }

        self.repo.record_audit(
            AuditEvent(
                actor_id=actor_id,
                actor_role=actor_role.value,
                case_id=case_id,
                action="report.exported",
                object_id=case_id,
                metadata={"format": export_format, "entities_count": len(entities)},
            )
        )

        fmt = export_format.lower().strip()
        if fmt == "markdown" or fmt == "md":
            dossier["formatted_output"] = self._render_markdown_dossier(dossier)
        elif fmt == "csv":
            dossier["formatted_output"] = self._render_csv_entities(entities)
        else:
            dossier["formatted_output"] = json.dumps(dossier, indent=2, ensure_ascii=False)

        return dossier

    @staticmethod
    def _render_markdown_dossier(dossier: dict[str, Any]) -> str:
        c = dossier["case"]
        lines = [
            f"# 𓂀 God's Eye OSINT Investigative Dossier — {c['title']}",
            "",
            f"- **Case ID:** `{c['id']}`",
            f"- **Owner:** `{c['owner']}`",
            f"- **Status:** `{c['status']}`",
            f"- **Legal Basis (LGPD/GDPR):** `{c['legal_basis']}`",
            f"- **Purpose:** {c['purpose']}",
            f"- **Generated At:** `{dossier['report_metadata']['generated_at']}`",
            "",
            "## 1. Correlation Findings & Risk Alerts",
        ]
        if not dossier["findings"]:
            lines.append("- No high-risk correlation alerts triggered.")
        else:
            for f in dossier["findings"]:
                lines.append(
                    f"- **[{f['risk'].upper()}] {f['title']}** (`{f['rule_id']}`, conf={f['confidence']}): {f['description']}"
                )

        lines.extend(["", "## 2. Resolved Entities", "", "| Type | Canonical Value | Confidence | Sources |", "|---|---|---|---|"])
        for ent in dossier["entities"]:
            srcs = ", ".join(ent["sources"])
            lines.append(
                f"| `{ent['type']}` | `{ent['canonical_value']}` | {ent['confidence']:.2f} | {srcs} |"
            )

        lines.extend(
            [
                "",
                "## 3. Investigative Graph (Mermaid)",
                "",
                "```mermaid",
                dossier["graph"]["mermaid"],
                "```",
                "",
                "## 4. Provenance & Raw Evidence Hashes (SHA-256)",
                "",
                "| Source | Retrieved At | Content Hash (SHA-256) | URL |",
                "|---|---|---|---|",
            ]
        )
        for ev in dossier["evidence"]:
            lines.append(
                f"| `{ev['source_id']}` | `{ev['retrieved_at']}` | `{ev['content_hash'][:20]}...` | {ev['url'] or 'N/A'} |"
            )
        return "\n".join(lines)

    @staticmethod
    def _render_csv_entities(entities: list[dict[str, Any]]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "type", "canonical_value", "confidence", "sources", "first_seen"])
        for e in entities:
            writer.writerow(
                [
                    e["id"],
                    e["type"],
                    e["canonical_value"],
                    e["confidence"],
                    ";".join(e["sources"]),
                    e["first_seen"],
                ]
            )
        return buf.getvalue()
