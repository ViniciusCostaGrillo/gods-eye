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
        elif fmt == "html":
            dossier["formatted_output"] = self._render_html_dossier(dossier)
        else:
            dossier["formatted_output"] = json.dumps(dossier, indent=2, ensure_ascii=False)

        return dossier

    @staticmethod
    def _render_html_dossier(dossier: dict[str, Any]) -> str:
        """Render a modern, standalone cyber-themed HTML dossier with embedded Mermaid graph and consolidated summary."""
        c = dossier["case"]
        meta = dossier["report_metadata"]
        summary = dossier["summary"]
        mermaid_code = dossier["graph"]["mermaid"]

        # Entities rows
        ent_rows = []
        for ent in dossier["entities"]:
            srcs = ", ".join(ent["sources"])
            ent_rows.append(
                f"<tr><td><span class='badge type'>{ent['type']}</span></td>"
                f"<td class='canonical'><strong>{ent['canonical_value']}</strong></td>"
                f"<td>{ent['confidence'] * 100:.0f}%</td>"
                f"<td><span class='dim'>{srcs}</span></td></tr>"
            )

        # Findings
        finding_cards = []
        for f in dossier["findings"]:
            risk = f["risk"].upper()
            finding_cards.append(
                f"<div class='alert-card risk-{risk.lower()}'>"
                f"<div class='alert-header'><span class='badge risk'>{risk}</span> <strong>{f['title']}</strong> "
                f"<span class='dim'>({f['rule_id']})</span></div>"
                f"<div class='alert-desc'>{f['description']}</div>"
                f"</div>"
            )

        # Evidence
        ev_rows = []
        for ev in dossier["evidence"][:25]:
            url_link = f"<a href='{ev['url']}' target='_blank'>{ev['url'][:65]}...</a>" if ev.get("url") else "N/A"
            ev_rows.append(
                f"<tr><td><code>{ev['source_id']}</code></td>"
                f"<td><code>{ev['content_hash'][:16]}...</code></td>"
                f"<td>{url_link}</td>"
                f"<td class='dim'>{ev['retrieved_at'][:19]}</td></tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>God's Eye (𓂀) — {c['title']}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <script>mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});</script>
  <style>
    :root {{
      --bg: #0d1117; --panel-bg: #161b22; --border: #30363d;
      --gold: #d29922; --cyan: #58a6ff; --green: #3fb950; --red: #f85149;
      --text: #c9d1d9; --text-bright: #f0f6fc;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg); color: var(--text); margin: 0; padding: 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      background: var(--panel-bg); border: 1px solid var(--gold); border-radius: 8px;
      padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    }}
    .header h1 {{ margin: 0 0 12px 0; color: var(--gold); font-size: 24px; }}
    .meta-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;
      font-size: 14px;
    }}
    .panel {{
      background: var(--panel-bg); border: 1px solid var(--border); border-radius: 8px;
      padding: 20px 24px; margin-bottom: 24px;
    }}
    .panel h2 {{ margin-top: 0; color: var(--cyan); font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
    .summary-card {{ border-color: var(--cyan); }}
    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;
    }}
    .badge.type {{ background: #1f6feb; color: white; }}
    .badge.risk {{ background: #da3633; color: white; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 12px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }}
    th {{ color: var(--gold); background: rgba(255,255,255,0.02); }}
    .dim {{ color: #8b949e; }}
    a {{ color: var(--cyan); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .alert-card {{
      background: rgba(248,81,73,0.08); border-left: 4px solid var(--red);
      padding: 12px 16px; margin-bottom: 12px; border-radius: 4px;
    }}
    .mermaid {{ background: #0b0e14; padding: 16px; border-radius: 6px; overflow-x: auto; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>𓂀 God's Eye — Dossiê Investigativo de Inteligência OSINT</h1>
      <div class="meta-grid">
        <div><span class="dim">Caso:</span> <strong>{c['title']}</strong></div>
        <div><span class="dim">ID do Caso:</span> <code>{c['id'][:12]}...</code></div>
        <div><span class="dim">Base Legal (LGPD):</span> <span class="badge" style="background:#238636;color:white">{c['legal_basis']}</span></div>
        <div><span class="dim">Gerado em:</span> {meta['generated_at'][:19]} UTC</div>
      </div>
    </div>

    <div class="panel summary-card">
      <h2>𓂀 FICHA CONSOLIDADA DO ALVO (RESUMO EXECUTIVO)</h2>
      <div class="meta-grid">
        <div><strong>Alvos Monitorados:</strong> {summary['targets_count']}</div>
        <div><strong>Entidades Extraídas:</strong> {summary['entities_count']}</div>
        <div><strong>Conexões no Grafo:</strong> {summary['relationships_count']}</div>
        <div><strong>Alertas & Correlações:</strong> {summary['findings_count']}</div>
      </div>
    </div>

    <div class="panel">
      <h2>𓂀 Grafo Interativo de Vínculos</h2>
      <div class="mermaid">
{mermaid_code}
      </div>
    </div>

    <div class="panel">
      <h2>𓂀 Entidades Identificadas ({len(dossier['entities'])})</h2>
      <table>
        <thead><tr><th>Tipo</th><th>Valor Canônico</th><th>Confiança</th><th>Fontes</th></tr></thead>
        <tbody>
          {"".join(ent_rows)}
        </tbody>
      </table>
    </div>

    {f"<div class='panel'><h2>𓂀 Alertas e Notas Investigativas ({len(dossier['findings'])})</h2>{''.join(finding_cards)}</div>" if finding_cards else ""}

    <div class="panel">
      <h2>𓂀 Proveniência e Evidências Brutas (SHA-256)</h2>
      <table>
        <thead><tr><th>Fonte</th><th>Hash (SHA-256)</th><th>URL Original</th><th>Coletado em</th></tr></thead>
        <tbody>
          {"".join(ev_rows)}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

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
