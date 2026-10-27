"""Cross-Platform CLI & Interactive Shell for God's Eye (𓂀) OSINT Platform."""

import asyncio
import shlex
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from godseye.api.app import AppContainer, create_app
from godseye.core.banner import (
    EYE_OF_HORUS_GLYPH,
    configure_terminal_utf8,
    render_banner,
)
from godseye.domain.enums import (
    LegalBasis,
    RiskLevel,
    Role,
    TargetType,
    VerificationStatus,
)
from godseye.services.case_service import detect_target_type

configure_terminal_utf8()
console = Console()

app = typer.Typer(
    name="godseye",
    help=f"{EYE_OF_HORUS_GLYPH} God's Eye — Cross-Platform OSINT Aggregation, Correlation & Threat Intelligence CLI (Windows CMD, PowerShell & Linux).",
    add_completion=False,
    no_args_is_help=False,
)


def _display_quick_help() -> None:
    table = Table(
        title=f"{EYE_OF_HORUS_GLYPH} God's Eye OSINT Commands (CMD / PowerShell / Linux)",
        border_style="cyan",
        header_style="bold gold1",
    )
    table.add_column("Command", style="bold bright_cyan")
    table.add_column("Description", style="white")
    table.add_column("Example", style="dim")

    table.add_row(
        "godseye scan <target>",
        "Run cascading OSINT on Email, Domain, IP, CNPJ, CEP, Username, Phone, Crypto, or Image",
        "godseye scan +5511999998888",
    )
    table.add_row(
        "godseye watchlist",
        "Manage continuous OSINT watchlists & alert rules (13 monitored event types)",
        "godseye watchlist --create 'VIP Domains' --targets example.com",
    )
    table.add_row(
        "godseye alerts",
        "View and acknowledge continuous monitoring OSINT alerts",
        "godseye alerts",
    )
    table.add_row(
        "godseye brazuca",
        "Import & approve candidate Brazilian sources from OSINT Brazuca catalog",
        "godseye brazuca --import",
    )
    table.add_row(
        "godseye quality <case_id>",
        "Compute Data Quality Scores & inter-source conflict reports",
        "godseye quality <case_id>",
    )
    table.add_row(
        "godseye ai-assist <case_id>",
        "Generate auditable assistive AI summaries/hypotheses (model_generated + human review)",
        "godseye ai-assist <case_id> --task executive_summary",
    )
    table.add_row(
        "godseye collaborate <case_id>",
        "Add analyst @mention comments, tasks, verifications, and case snapshots",
        "godseye collaborate <case_id> --comment 'Verified @alice'",
    )
    table.add_row(
        "godseye sources",
        "Browse the 100+ Global & Brazilian OSINT APIs catalog",
        "godseye sources --region brasil",
    )
    table.add_row(
        "godseye cases",
        "List all investigative cases & legal bases",
        "godseye cases",
    )
    table.add_row(
        "godseye graph <case_id>",
        "Render the investigative entity relationship graph & Mermaid diagram",
        "godseye graph <case_id>",
    )
    table.add_row(
        "godseye timeline <case_id>",
        "Display chronological OSINT collection & correlation timeline",
        "godseye timeline <case_id>",
    )
    table.add_row(
        "godseye report <case_id>",
        "Export auditable OSINT dossier (JSON, Markdown, CSV)",
        "godseye report <case_id> --format md",
    )
    table.add_row(
        "godseye audit",
        "Inspect immutable RBAC & LGPD compliance audit trail",
        "godseye audit",
    )
    table.add_row(
        "godseye benchmark",
        "Run performance, cache & rate-limit resilience diagnostics",
        "godseye benchmark",
    )
    table.add_row(
        "godseye shell",
        "Launch interactive Eye of Horus analyst console",
        "godseye shell",
    )
    table.add_row(
        "godseye serve",
        "Launch the FastAPI /api/v1 REST backend server",
        "godseye serve --port 8000",
    )
    console.print(table)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and Eye of Horus emblem"),
) -> None:
    """God's Eye (𓂀) OSINT Cybersecurity CLI."""
    if version:
        render_banner(console)
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        render_banner(console)
        _display_quick_help()


@app.command("banner")
def cmd_banner() -> None:
    """Render the Eye of Horus (Olho de Hórus 𓂀) emblem."""
    render_banner(console)


@app.command("scan")
def cmd_scan(
    target_value: str = typer.Argument(..., help="Target value (email, domain, IP, CNPJ, CEP, username)"),
    case_title: str = typer.Option(
        "", "--case", "-c", help="Case title (auto-created if not specified)"
    ),
    target_type: str | None = typer.Option(
        None, "--type", "-t", help="Explicit target type (email, domain, ip, cnpj, cep, username)"
    ),
    depth: int = typer.Option(2, "--depth", "-d", min=1, max=3, help="Cascading discovery depth (1-3)"),
    sources: str | None = typer.Option(
        None, "--sources", "-s", help="Comma-separated list of source IDs to run"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Export dossier to file (.json, .md, .csv)"
    ),
    export_format: str = typer.Option(
        "json", "--format", "-f", help="Dossier export format (json, md, csv)"
    ),
    legal_basis: LegalBasis = typer.Option(
        LegalBasis.CYBERSECURITY_DEFENSE,
        "--legal-basis",
        help="LGPD/GDPR legal basis for investigation",
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress banner output"),
) -> None:
    """Execute a cascading OSINT investigation on a target with full provenance and correlation."""
    if not no_banner:
        render_banner(console)

    resolved_type = TargetType(target_type.lower()) if target_type else detect_target_type(target_value)
    selected_sources = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
    title = case_title or f"OSINT Investigation: {target_value} ({resolved_type.value})"

    async def _run() -> None:
        container = AppContainer()
        try:
            case = container.case_service.create_case(
                title=title,
                legal_basis=legal_basis,
                actor_role=Role.INVESTIGATOR,
            )
            target = container.case_service.add_target(
                case_id=case.id,
                value=target_value,
                target_type=resolved_type,
                actor_role=Role.INVESTIGATOR,
            )

            console.print(
                f"\n[bold bright_cyan]{EYE_OF_HORUS_GLYPH} Case Created:[/bold bright_cyan] [gold1]{case.id}[/gold1] "
                f"| [bold]Target:[/bold] [bright_white]{target.normalized_value}[/bright_white] ([cyan]{target.type.value}[/cyan]) "
                f"| [bold]Depth:[/bold] {depth} | [bold]Legal Basis:[/bold] {case.legal_basis.value}"
            )

            summary = await container.orchestrator.investigate_target(
                case_id=case.id,
                target=target,
                max_depth=depth,
                selected_sources=selected_sources,
                actor_role=Role.INVESTIGATOR,
            )

            # 1. Collection Jobs Table
            jobs_table = Table(
                title=f"{EYE_OF_HORUS_GLYPH} Executed OSINT Source Adapters",
                border_style="gold1",
                header_style="bold bright_cyan",
            )
            jobs_table.add_column("Source ID", style="bold cyan")
            jobs_table.add_column("Status", style="bold")
            jobs_table.add_column("Duration (ms)", justify="right")
            jobs_table.add_column("Idempotency Hash", style="dim")

            for j in summary["jobs"]:
                st = j["status"]
                color = "green" if st in {"completed", "cached"} else "red"
                jobs_table.add_row(
                    j["source_id"],
                    f"[{color}]{st.upper()}[/{color}]",
                    f"{j['duration_ms']:.1f}",
                    j["idempotency_key"][:16] + "...",
                )
            console.print(jobs_table)

            # 2. Resolved Entities Table
            entities = container.repo.list_entities(case.id)
            ent_table = Table(
                title=f"{EYE_OF_HORUS_GLYPH} Deduplicated Entities ({len(entities)})",
                border_style="cyan",
                header_style="bold gold1",
            )
            ent_table.add_column("Entity Type", style="bold bright_cyan")
            ent_table.add_column("Canonical Value", style="bright_white")
            ent_table.add_column("Confidence", justify="right", style="green")
            ent_table.add_column("Corroborating Sources", style="yellow")

            for ent in entities:
                ent_table.add_row(
                    ent.type.value,
                    ent.canonical_value,
                    f"{ent.confidence:.2f}",
                    ", ".join(ent.sources),
                )
            console.print(ent_table)

            # 3. Investigative Graph Tree
            graph_data = container.reporting.get_graph(case.id)
            tree = Tree(
                f"[bold gold1]{EYE_OF_HORUS_GLYPH} Investigative Correlation Graph (Case {case.id[:8]})[/bold gold1]"
            )
            for edge in graph_data["edges"]:
                tree.add(
                    f"[cyan]{edge['from_label']}[/cyan] "
                    f"[dim]──([bold gold1]{edge['relation']}[/bold gold1] • {edge['source_id']})──►[/dim] "
                    f"[bright_white]{edge['to_label']}[/bright_white]"
                )
            console.print(Panel(tree, border_style="cyan"))

            # 4. Correlation Findings & Risk Alerts
            findings = summary["findings"]
            if findings:
                find_table = Table(
                    title=f"{EYE_OF_HORUS_GLYPH} Correlation Engine Alerts ({len(findings)})",
                    border_style="red",
                    header_style="bold bright_red",
                )
                find_table.add_column("Rule ID", style="bold yellow")
                find_table.add_column("Risk", style="bold")
                find_table.add_column("Title", style="bold white")
                find_table.add_column("Description", style="white")
                for f in findings:
                    r_lvl = f["risk"].upper()
                    r_col = "bright_red" if r_lvl in {"HIGH", "CRITICAL"} else "yellow"
                    find_table.add_row(
                        f["rule_id"],
                        f"[{r_col}]{r_lvl}[/{r_col}]",
                        f["title"],
                        f["description"],
                    )
                console.print(find_table)

            # Optional Dossier File Export
            if output:
                dossier = container.reporting.generate_dossier(
                    case_id=case.id,
                    export_format=export_format,
                    actor_role=Role.INVESTIGATOR,
                )
                out_path = Path(output)
                out_path.write_text(dossier["formatted_output"], encoding="utf-8")
                console.print(
                    f"[bold green]✔ Auditable OSINT Dossier exported to:[/bold green] {out_path.resolve()}"
                )
        finally:
            await container.shutdown()

    asyncio.run(_run())


@app.command("sources")
def cmd_sources(
    region: str | None = typer.Option(
        None, "--region", "-r", help="Filter by region: 'global' or 'brasil'"
    ),
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter by category substring (e.g. DNS, Vazamentos, CNPJ)"
    ),
    live_only: bool = typer.Option(
        False, "--live", "-l", help="Show only sources with active live adapters"
    ),
) -> None:
    """List the catalog of 100+ Global & Brazilian OSINT APIs."""
    container = AppContainer()
    try:
        items = container.registry.list_sources(
            region=region, category=category, live_only=live_only
        )
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} God's Eye OSINT Catalog ({len(items)} Sources)",
            border_style="gold1",
            header_style="bold bright_cyan",
        )
        table.add_column("ID", style="bold cyan")
        table.add_column("Region", style="magenta")
        table.add_column("Category", style="gold1")
        table.add_column("Name", style="bold white")
        table.add_column("Auth", style="yellow")
        table.add_column("Live Adapter", justify="center")
        table.add_column("Description", style="dim")

        for s in items:
            live_badge = "[bold green]ACTIVE[/bold green]" if s.has_live_adapter else "[dim]CATALOG[/dim]"
            table.add_row(
                s.id,
                s.region.upper(),
                s.category,
                s.name,
                s.auth_type,
                live_badge,
                s.description[:70],
            )
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("cases")
def cmd_cases() -> None:
    """List all investigative cases stored in God's Eye."""
    container = AppContainer()
    try:
        cases = container.case_service.list_cases()
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Investigative Cases ({len(cases)})",
            border_style="cyan",
            header_style="bold gold1",
        )
        table.add_column("Case ID", style="bold cyan")
        table.add_column("Title", style="white")
        table.add_column("Status", style="green")
        table.add_column("Legal Basis (LGPD)", style="yellow")
        table.add_column("Created At", style="dim")

        for c in cases:
            table.add_row(
                c.id,
                c.title,
                c.status.value.upper(),
                c.legal_basis.value,
                c.created_at,
            )
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("graph")
def cmd_graph(
    case_id: str = typer.Argument(..., help="Case ID to render graph for"),
    mermaid: bool = typer.Option(False, "--mermaid", "-m", help="Output Mermaid flowchart syntax"),
) -> None:
    """Display the investigative entity relationship graph for a case."""
    container = AppContainer()
    try:
        graph_data = container.reporting.get_graph(case_id)
        if mermaid:
            console.print(graph_data["mermaid"])
        else:
            console.print(
                Panel(
                    graph_data["ascii_graph"],
                    title=f"{EYE_OF_HORUS_GLYPH} Graph for Case {case_id} ({graph_data['nodes_count']} nodes, {graph_data['edges_count']} edges)",
                    border_style="gold1",
                )
            )
    finally:
        asyncio.run(container.shutdown())


@app.command("timeline")
def cmd_timeline(
    case_id: str = typer.Argument(..., help="Case ID to display timeline for"),
) -> None:
    """Display chronological timeline of targets, evidence, and correlations for a case."""
    container = AppContainer()
    try:
        events = container.reporting.get_timeline(case_id)
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Investigative Timeline — Case {case_id}",
            border_style="cyan",
            header_style="bold gold1",
        )
        table.add_column("Timestamp", style="dim")
        table.add_column("Event Type", style="bold cyan")
        table.add_column("Source", style="yellow")
        table.add_column("Summary", style="white")
        for ev in events:
            table.add_row(ev["timestamp"], ev["event_type"], ev["source"], ev["summary"])
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("report")
def cmd_report(
    case_id: str = typer.Argument(..., help="Case ID to export dossier for"),
    export_format: str = typer.Option("md", "--format", "-f", help="Format: json, md, csv"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate and export an auditable OSINT dossier (JSON, Markdown, or CSV)."""
    container = AppContainer()
    try:
        dossier = container.reporting.generate_dossier(
            case_id=case_id,
            export_format=export_format,
            actor_role=Role.INVESTIGATOR,
        )
        if output:
            out_path = Path(output)
            out_path.write_text(dossier["formatted_output"], encoding="utf-8")
            console.print(f"[bold green]✔ Dossier written to:[/bold green] {out_path.resolve()}")
        else:
            console.print(dossier["formatted_output"])
    finally:
        asyncio.run(container.shutdown())


@app.command("audit")
def cmd_audit(
    case_id: str | None = typer.Option(None, "--case", "-c", help="Filter audit log by Case ID"),
) -> None:
    """Display immutable security, RBAC & LGPD compliance audit logs."""
    container = AppContainer()
    try:
        logs = container.case_service.list_audit_log(case_id=case_id, actor_role=Role.AUDITOR)
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Immutable Security & Compliance Audit Trail ({len(logs)} events)",
            border_style="gold1",
            header_style="bold bright_cyan",
        )
        table.add_column("Timestamp", style="dim")
        table.add_column("Actor", style="cyan")
        table.add_column("Role", style="yellow")
        table.add_column("Action", style="bold green")
        table.add_column("Case ID", style="white")
        for entry in logs[:40]:
            table.add_row(
                entry["timestamp"],
                entry["actor_id"],
                entry["actor_role"],
                entry["action"],
                entry["case_id"] or "-",
            )
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("benchmark")
def cmd_benchmark() -> None:
    """Run performance, multi-tier cache & rate-limit resilience self-diagnostics."""
    render_banner(console)

    async def _run_bench() -> None:
        container = AppContainer(db_path=":memory:")
        try:
            case = container.case_service.create_case(title="Performance Benchmark Case")
            target = container.case_service.add_target(case.id, "example.com", TargetType.DOMAIN)

            # Cold run
            await container.orchestrator.investigate_target(case.id, target, max_depth=1)
            # Warm cached run
            await container.orchestrator.investigate_target(case.id, target, max_depth=1)

            snap = container.http_client.telemetry.snapshot()
            table = Table(
                title=f"{EYE_OF_HORUS_GLYPH} Performance & Resilience Telemetry Snapshot",
                border_style="cyan",
                header_style="bold gold1",
            )
            table.add_column("Metric", style="bold bright_cyan")
            table.add_column("Value", style="bright_white")
            table.add_row("Total Adapter Invocations", str(snap["total_requests"]))
            table.add_row("Cache Hits (L1 LRU + L2 SQLite)", f"{snap['total_cache_hits']} ({snap['cache_hit_rate_pct']}%)")
            table.add_row("p50 Latency (ms)", str(snap["p50_latency_ms"]))
            table.add_row("p95 Latency (ms)", str(snap["p95_latency_ms"]))
            table.add_row("p99 Latency (ms)", str(snap["p99_latency_ms"]))
            console.print(table)
        finally:
            await container.shutdown()

    asyncio.run(_run_bench())


@app.command("shell")
def cmd_shell() -> None:
    """Start an interactive God's Eye (𓂀) OSINT shell compatible with CMD, PowerShell & Linux."""
    render_banner(console)
    console.print(
        "[bold gold1]Interactive Analyst Console started.[/bold gold1] "
        "Type [cyan]scan <target>[/cyan], [cyan]sources[/cyan], [cyan]cases[/cyan], [cyan]audit[/cyan], [cyan]help[/cyan], or [cyan]exit[/cyan].\n"
    )
    while True:
        try:
            line = console.input(f"[bold gold1]{EYE_OF_HORUS_GLYPH} godseye>[/bold gold1] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Closing Eye of Horus console.[/dim]")
            break

        if not line:
            continue
        if line.lower() in {"exit", "quit", "q"}:
            console.print("[dim]Closing Eye of Horus console.[/dim]")
            break
        if line.lower() == "help":
            _display_quick_help()
            continue

        try:
            args = shlex.split(line)
            if args and args[0] == "scan" and "--no-banner" not in args:
                args.append("--no-banner")
            app(args=args, standalone_mode=False)
        except SystemExit:
            pass
        except Exception as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
) -> None:
    """Launch the FastAPI /api/v1 OSINT backend server."""
    import uvicorn

    render_banner(console)
    console.print(
        f"[bold green]Starting God's Eye FastAPI v1 server on http://{host}:{port} (Docs: http://{host}:{port}/docs)[/bold green]"
    )
    fastapi_app = create_app()
    uvicorn.run(fastapi_app, host=host, port=port)


@app.command("watchlist")
def cmd_watchlist(
    target_value: str | None = typer.Option(None, "--create", "-n", help="Create a watchlist monitoring this target value"),
    case_id: str = typer.Option("global", "--case", "-c", help="Case ID to link watchlist"),
    frequency: str = typer.Option("realtime", "--freq", help="Frequency: realtime, hourly, daily"),
    min_risk: str = typer.Option("high", "--min-risk", help="Severity level (info, low, medium, high, critical)"),
) -> None:
    """Create or list continuous OSINT watchlists & alert rules (Expansion Module 1)."""
    container = AppContainer()
    try:
        if target_value:
            wl = container.watchlist_service.create_watchlist(
                case_id=case_id,
                value=target_value,
                frequency=frequency,
                severity=RiskLevel(min_risk.lower()),
            )
            console.print(
                f"[bold green]✔ Watchlist created:[/bold green] [gold1]{wl.id}[/gold1] monitoring {wl.value} ({wl.type.value})"
            )
        items = container.watchlist_service.list_watchlists()
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Continuous OSINT Watchlists ({len(items)})",
            border_style="gold1",
            header_style="bold bright_cyan",
        )
        table.add_column("Watchlist ID", style="bold cyan")
        table.add_column("Case ID", style="white")
        table.add_column("Target Value", style="yellow")
        table.add_column("Type", style="green")
        table.add_column("Frequency", justify="right")
        for w in items:
            table.add_row(
                w.id,
                w.case_id,
                w.value,
                w.type.value.upper(),
                w.frequency,
            )
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("alerts")
def cmd_alerts(
    ack_id: str | None = typer.Option(None, "--ack", "-a", help="Acknowledge an alert by ID"),
    unack_only: bool = typer.Option(False, "--unack", "-u", help="Show only unacknowledged alerts"),
) -> None:
    """View and acknowledge continuous monitoring OSINT alerts (Expansion Module 1)."""
    container = AppContainer()
    try:
        if ack_id:
            updated = container.watchlist_service.acknowledge_alert(ack_id)
            if updated:
                console.print(f"[bold green]✔ Alert acknowledged:[/bold green] {updated.id}")
        items = container.watchlist_service.list_alerts(unacknowledged_only=unack_only)
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Watchlist Continuous Monitoring Alerts ({len(items)})",
            border_style="red",
            header_style="bold bright_red",
        )
        table.add_column("Alert ID", style="bold cyan")
        table.add_column("Source", style="gold1")
        table.add_column("Severity", style="bold red")
        table.add_column("Message", style="white")
        table.add_column("Ack", justify="center")
        for a in items:
            ack_str = "[green]YES[/green]" if a.acknowledged_at else "[bold red]NO[/bold red]"
            table.add_row(a.id, a.source_id, a.severity.value.upper(), a.message, ack_str)
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("brazuca")
def cmd_brazuca(
    do_import: bool = typer.Option(False, "--import", "-i", help="Import candidate sources from OSINT Brazuca"),
    approve_id: str | None = typer.Option(None, "--approve", "-a", help="Approve a candidate source ID after human review"),
) -> None:
    """Import & govern candidate Brazilian sources from OSINT Brazuca (Expansion Module 3)."""
    container = AppContainer()
    try:
        if do_import:
            imported = container.registry.import_brazuca_catalog()
            console.print(
                f"[bold green]✔ Imported {len(imported)} OSINT Brazuca sources as CANDIDATE (pending human review).[/bold green]"
            )
        if approve_id:
            approved = container.registry.approve_candidate_source(approve_id)
            if approved:
                console.print(
                    f"[bold green]✔ Approved source {approved.id}:[/bold green] status={approved.status.value}, enabled={approved.enabled}"
                )
        brazuca_sources = [
            s for s in container.registry.list_sources(region="brasil")
            if s.id.startswith("brazuca_")
        ]
        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} OSINT Brazuca Dynamic Catalog ({len(brazuca_sources)} Candidate/Reviewed Sources)",
            border_style="gold1",
            header_style="bold bright_cyan",
        )
        table.add_column("Source ID", style="bold cyan")
        table.add_column("Name", style="white")
        table.add_column("Category", style="gold1")
        table.add_column("Review Status", style="yellow")
        table.add_column("Enabled", justify="center")
        for s in brazuca_sources:
            en_badge = "[green]YES[/green]" if s.enabled else "[red]NO[/red]"
            table.add_row(s.id, s.name, s.category, s.status.value.upper(), en_badge)
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


@app.command("quality")
def cmd_quality(
    case_id: str = typer.Argument(..., help="Case ID to evaluate data quality & conflicts"),
) -> None:
    """Compute Data Quality Scores & inter-source conflict reports for a case (Expansion Module 7)."""
    container = AppContainer()
    try:
        res = container.governance_service.evaluate_case_governance(case_id)
        scores_table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Data Quality Scores — Case {case_id} ({res['scores_calculated']} observations)",
            border_style="cyan",
            header_style="bold gold1",
        )
        scores_table.add_column("Observation ID", style="cyan")
        scores_table.add_column("Final Score", justify="right", style="bold green")
        scores_table.add_column("Source Trust", justify="right")
        scores_table.add_column("Recency", justify="right")
        scores_table.add_column("Corroboration", justify="right")
        scores_table.add_column("Explanation", style="dim")
        for s in res["scores"]:
            scores_table.add_row(
                (s["observation_id"] or "-")[:12],
                f"{s['final_score']:.3f}",
                f"{s['source_trust']:.2f}",
                f"{s['recency']:.2f}",
                str(s["corroboration_count"]),
                s["explanation"],
            )
        console.print(scores_table)

        if res["conflicts"]:
            conf_table = Table(
                title=f"{EYE_OF_HORUS_GLYPH} Detected Inter-Source Conflicts ({res['conflicts_detected']})",
                border_style="red",
                header_style="bold bright_red",
            )
            conf_table.add_column("Entity ID", style="bold yellow")
            conf_table.add_column("Conflict Type", style="cyan")
            conf_table.add_column("Description", style="white")
            for c in res["conflicts"]:
                conf_table.add_row(c["entity_id"], c["conflict_type"], c["description"])
            console.print(conf_table)
    finally:
        asyncio.run(container.shutdown())


@app.command("ai-assist")
def cmd_ai_assist(
    case_id: str = typer.Argument(..., help="Case ID for assistive AI analysis"),
    task_type: str = typer.Option(
        "dossier_summary",
        "--task",
        "-t",
        help="Task: dossier_summary, hypothesis_suggestion, conflict_explanation, query_translation",
    ),
    approve_id: str | None = typer.Option(None, "--approve", "-a", help="Approve an AI inference ID after human review"),
) -> None:
    """Generate or review auditable Assistive AI analysis (marked model_generated; requires human review)."""
    container = AppContainer()
    try:
        if approve_id:
            reviewed = container.ai_service.review_inference(
                approve_id, decision="approved", reviewer_id="sec-analyst"
            )
            if reviewed:
                console.print(
                    f"[bold green]✔ AI Inference {reviewed.id} reviewed:[/bold green] status={reviewed.human_review_status}"
                )
        else:
            inf = container.ai_service.generate_case_analysis(case_id=case_id, task_type=task_type)
            console.print(
                Panel(
                    f"[bold yellow]confidence_kind={inf.confidence_kind} | human_review_status={inf.human_review_status.upper()}[/bold yellow]\n"
                    f"[dim]Evidence IDs cited: {len(inf.input_evidence_ids)} | Prompt Hash: {inf.prompt_hash[:16]}...[/dim]\n\n"
                    f"{inf.output}",
                    title=f"{EYE_OF_HORUS_GLYPH} Assistive AI ({inf.task_type}) — ID: {inf.id}",
                    border_style="gold1",
                )
            )
    finally:
        asyncio.run(container.shutdown())


@app.command("collaborate")
def cmd_collaborate(
    case_id: str = typer.Argument(..., help="Case ID to collaborate on"),
    comment: str | None = typer.Option(None, "--comment", "-m", help="Add comment (supports @mentions)"),
    task_title: str | None = typer.Option(None, "--task", "-t", help="Create an investigative task"),
    assignee: str = typer.Option("sec-analyst", "--assignee", help="Task assignee"),
    verify_subject: str | None = typer.Option(None, "--verify", "-v", help="Entity ID to record 4-eyes verification"),
    verify_status: str = typer.Option("corroborated", "--status", help="Verification status: corroborated, contested, false_positive"),
    snapshot_note: str | None = typer.Option(None, "--snapshot", "-s", help="Create a versioned case snapshot with note"),
) -> None:
    """Collaborate on a case: @mention comments, tasks, 4-eyes verification, and snapshots (Expansion Module 6)."""
    container = AppContainer()
    try:
        if comment:
            c = container.collaboration_service.add_comment(case_id=case_id, body=comment)
            console.print(
                f"[bold green]✔ Comment added ({c.id}):[/bold green] mentions={c.mentions}"
            )
        if task_title:
            t = container.collaboration_service.create_task(
                case_id=case_id, title=task_title, assignee_id=assignee
            )
            console.print(
                f"[bold green]✔ Investigative Task created ({t.id}):[/bold green] {t.title} -> @{t.assignee_id}"
            )
        if verify_subject:
            v = container.collaboration_service.verify_finding(
                case_id=case_id,
                entity_id=verify_subject,
                status=VerificationStatus(verify_status.lower()),
                reason="4-eyes analyst verification via CLI",
            )
            console.print(
                f"[bold green]✔ Verification recorded ({v.id}):[/bold green] {v.entity_id} = {v.status.value.upper()}"
            )
        if snapshot_note:
            dossier = container.reporting.generate_dossier(case_id=case_id)
            snap = container.collaboration_service.create_case_version(
                case_id=case_id, change_summary=snapshot_note, dossier_payload=dossier
            )
            console.print(
                f"[bold green]✔ Case Version v{snap.version} saved ({snap.id}):[/bold green] hash={snap.snapshot_hash[:16]}..."
            )

        comments = container.collaboration_service.list_comments(case_id)
        tasks = container.collaboration_service.list_tasks(case_id)
        verifications = container.collaboration_service.list_verifications(case_id)
        versions = container.collaboration_service.list_case_versions(case_id)
        console.print(
            f"[cyan]Collaboration Summary for Case {case_id}:[/cyan] "
            f"{len(comments)} comment(s), {len(tasks)} task(s), "
            f"{len(verifications)} verification(s), {len(versions)} snapshot version(s)."
        )
    finally:
        asyncio.run(container.shutdown())


def app_entry() -> None:
    """Console script entry point."""
    configure_terminal_utf8()
    app()


if __name__ == "__main__":
    app_entry()
