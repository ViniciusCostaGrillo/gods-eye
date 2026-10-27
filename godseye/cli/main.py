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
from godseye.domain.enums import LegalBasis, Role, TargetType
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
        "Run cascading OSINT investigation on Email, Domain, IP, CNPJ, CEP, or Username",
        "godseye scan example.com",
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


def app_entry() -> None:
    """Console script entry point."""
    configure_terminal_utf8()
    app()


if __name__ == "__main__":
    app_entry()
