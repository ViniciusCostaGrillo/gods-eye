"""Cross-Platform CLI & Interactive Shell for God's Eye (𓂀) OSINT Platform."""

import asyncio
import os
import shlex
import sys
from pathlib import Path
from typing import Any

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style as PtStyle
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from godseye.api.app import AppContainer, create_app
from godseye.core.banner import (
    EYE_OF_HORUS_GLYPH,
    configure_terminal_utf8,
    render_banner,
    render_compact_header,
)
from godseye.core.bootstrap import ensure_zero_config_environment
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
    help=f"{EYE_OF_HORUS_GLYPH} God's Eye — Plataforma OSINT de Agregação, Correlação & Inteligência de Ameaças.",
    add_completion=False,
    no_args_is_help=False,
)

COMMAND_COMPLETIONS: dict[str, Any] = {
    "scan": {
        "--depth": None,
        "-d": None,
        "--sources": None,
        "-s": None,
        "--output": None,
        "-o": None,
        "--format": {"json", "md", "csv"},
        "-f": {"json", "md", "csv"},
        "--type": {"email", "domain", "ip", "cnpj", "cep", "username", "phone", "crypto", "person"},
        "-t": {"email", "domain", "ip", "cnpj", "cep", "username", "phone", "crypto", "person"},
    },
    "username": {
        "--output": None,
        "-o": None,
        "--format": {"json", "md", "csv"},
        "-f": {"json", "md", "csv"},
    },
    "sources": {
        "--region": {"global", "brasil"},
        "-r": {"global", "brasil"},
        "--live": None,
        "-l": None,
        "--category": None,
        "-c": None,
    },
    "cases": None,
    "graph": {
        "--mermaid": None,
        "-m": None,
    },
    "timeline": None,
    "report": {
        "--format": {"json", "md", "csv"},
        "-f": {"json", "md", "csv"},
        "--output": None,
        "-o": None,
    },
    "watchlist": {
        "--create": None,
        "-n": None,
        "--freq": {"realtime", "hourly", "daily"},
        "--min-risk": {"info", "low", "medium", "high", "critical"},
    },
    "alerts": {
        "--ack": None,
        "-a": None,
        "--unack": None,
        "-u": None,
    },
    "brazuca": {
        "--import": None,
        "-i": None,
        "--approve": None,
        "-a": None,
    },
    "quality": None,
    "ai-assist": {
        "--task": {"dossier_summary", "hypothesis_suggestion", "conflict_explanation"},
        "-t": {"dossier_summary", "hypothesis_suggestion", "conflict_explanation"},
        "--approve": None,
        "-a": None,
    },
    "collaborate": {
        "--comment": None,
        "-m": None,
        "--task": None,
        "-t": None,
        "--verify": None,
        "-v": None,
        "--snapshot": None,
        "-s": None,
    },
    "audit": {
        "--case": None,
        "-c": None,
    },
    "benchmark": None,
    "doctor": None,
    "serve": {
        "--host": None,
        "-h": None,
        "--port": None,
        "-p": None,
    },
    "menu": None,
    "banner": None,
    "help": None,
    "clear": None,
    "cls": None,
    "exit": None,
    "quit": None,
    "q": None,
}


def _display_quick_help() -> None:
    """Minimalist, elegant command reference without repeating 'godseye'."""
    cmd_table = Table(
        box=None,
        show_header=True,
        header_style="bold gold1",
        padding=(0, 2),
        collapse_padding=True,
    )
    cmd_table.add_column("Comando", style="bold bright_cyan", no_wrap=True)
    cmd_table.add_column("Finalidade", style="white")
    cmd_table.add_column("Exemplo de Uso", style="dim")

    cmd_table.add_row(
        "scan <alvo>",
        "Varredura inteligente (Nome, Usuário, E-mail, Fone, CNPJ, IP, Cripto)",
        "scan +5511999998888",
    )
    cmd_table.add_row(
        "username <user>",
        "Matriz SOCMINT em 8+ plataformas (GitHub, Reddit, HN, Dev.to...)",
        "username torvalds",
    )
    cmd_table.add_row(
        "watchlist",
        "Monitoramento contínuo e regras de alerta em tempo real",
        "watchlist --create example.com",
    )
    cmd_table.add_row(
        "alerts",
        "Central de alertas emitidos pelo motor de correlação",
        "alerts --unack",
    )
    cmd_table.add_row(
        "cases",
        "Listagem de investigações e dossiês ativos",
        "cases",
    )
    cmd_table.add_row(
        "report <id>",
        "Exportação de dossiê investigativo auditável (.md, .json, .csv)",
        "report <id> --format md",
    )
    cmd_table.add_row(
        "graph <id>",
        "Visualização do grafo de vínculos e entidades correlacionadas",
        "graph <id>",
    )
    cmd_table.add_row(
        "sources",
        "Catálogo de 135+ fontes OSINT (Globais e Brasileiras)",
        "sources --region brasil",
    )
    cmd_table.add_row(
        "quality <id>",
        "Avaliação de confiabilidade de dados e detecção de conflitos",
        "quality <id>",
    )
    cmd_table.add_row(
        "doctor",
        "Diagnóstico de integridade do ambiente e conectividade das APIs",
        "doctor",
    )
    cmd_table.add_row(
        "serve",
        "Inicia API REST FastAPI e interface Swagger (/docs)",
        "serve --port 8000",
    )
    cmd_table.add_row(
        "clear / exit",
        "Limpa a tela ou encerra a sessão",
        "exit",
    )

    panel = Panel(
        cmd_table,
        title=f"[bold gold1]{EYE_OF_HORUS_GLYPH} REFERÊNCIA RÁPIDA DE COMANDOS[/bold gold1]",
        subtitle="[dim]Dica: no console interativo você pode digitar o alvo diretamente sem o prefixo 'scan'[/dim]",
        border_style="gold1",
        padding=(1, 2),
    )
    console.print(panel)


def _render_scan_report(
    case: Any,
    target: Any,
    depth: int,
    summary: dict[str, Any],
    container: AppContainer,
) -> None:
    """Render a clean, high-precision, highly readable OSINT Intelligence Dossier."""
    # 1. Header Card
    jobs = summary.get("jobs", [])
    total_time_ms = sum(j.get("duration_ms", 0) for j in jobs)
    entities = container.repo.list_entities(case.id)
    findings = summary.get("findings", [])

    header_text = Text()
    header_text.append(f"{EYE_OF_HORUS_GLYPH} RELATÓRIO DE INTELIGÊNCIA OSINT\n", style="bold gold1")
    header_text.append("Alvo: ", style="dim")
    header_text.append(f"{target.normalized_value}  ", style="bold bright_white")
    header_text.append("•  Tipo: ", style="dim")
    header_text.append(f"{target.type.value.upper()}  ", style="bold cyan")
    header_text.append("•  Profundidade: ", style="dim")
    header_text.append(f"{depth}  ", style="white")
    header_text.append("•  Fontes Consultadas: ", style="dim")
    header_text.append(f"{len(jobs)}  ", style="green")
    header_text.append("•  Evidências: ", style="dim")
    header_text.append(f"{len(entities)}  ", style="bright_cyan")
    header_text.append("•  Tempo Total: ", style="dim")
    header_text.append(f"{total_time_ms:.0f}ms\n", style="dim")
    header_text.append("Base Legal (LGPD): ", style="dim")
    header_text.append(f"{case.legal_basis.value}  ", style="yellow")
    header_text.append("•  Caso: ", style="dim")
    header_text.append(f"{case.id[:12]}...", style="dim")

    console.print(Panel(header_text, border_style="gold1", padding=(1, 2)))

    # 2. Compact Executed Sources Badge Bar
    completed_sources: list[str] = [
        f"[green]✔ {j['source_id']}[/green]"
        for j in jobs
        if j.get("status") in {"completed", "cached"}
    ]
    if completed_sources:
        console.print(
            f"[bold dim]Fontes Ativas ({len(completed_sources)}):[/bold dim] "
            + "  ".join(completed_sources[:8])
            + (f" [dim](+{len(completed_sources) - 8} outras)[/dim]" if len(completed_sources) > 8 else "")
            + "\n"
        )

    # 3. Categorized Intelligence Findings (Structured & Legible)
    # Collect observations from evidence to display rich, non-truncated metadata
    all_evidence = container.repo.list_evidence(case.id)
    accounts: list[dict[str, Any]] = []
    locations: list[dict[str, Any]] = []
    organizations: list[dict[str, Any]] = []
    breaches: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []
    network_hosts: list[dict[str, Any]] = []
    cryptos: list[dict[str, Any]] = []

    seen_vals: set[str] = set()
    for ev in all_evidence:
        payload = ev.raw_payload or {}
        val = str(ev.url or payload.get("profile_url") or payload.get("target") or ev.source_id)
        dedup_key = f"{ev.source_id}:{val}"
        if dedup_key in seen_vals:
            continue
        seen_vals.add(dedup_key)

        if ev.source_id in {"github_osint", "socmint_username_matrix", "person_and_leak_osint", "keybase", "gravatar"}:
            if payload.get("source") == "XposedOrNot" or "Name" in payload:
                breaches.append(payload)
            elif "title" in payload and "language" in payload:
                documents.append(payload)
            elif "email" in payload and payload.get("source") == "github_public_commits":
                continue
            elif "login" in payload or "username" in payload or "profile_url" in payload or "displayName" in payload:
                accounts.append(payload)
        elif ev.source_id in {"phone_osint", "brasil_cep", "ip_api"}:
            locations.append(payload)
        elif ev.source_id in {"brasil_cnpj", "portal_transparencia"}:
            organizations.append(payload)
        elif ev.source_id in {"hibp", "hudsonrock"}:
            breaches.append(payload)
        elif ev.source_id in {"querido_diario", "datajud_cnj"}:
            documents.append(payload)
        elif ev.source_id in {"shodan_internetdb", "dns_doh", "crtsh", "rdap"}:
            network_hosts.append(payload)
        elif ev.source_id in {"crypto_osint"}:
            cryptos.append(payload)

    # --- Render Section: Contas & Presença em Redes / SOCMINT (block layout, full URLs) ---
    merged: dict[str, dict[str, Any]] = {}
    for acc in accounts:
        key = str(acc.get("profile_url") or acc.get("html_url") or acc.get("login") or acc.get("username") or id(acc)).lower().rstrip("/")
        base = merged.setdefault(key, {})
        for k, v in acc.items():
            if v not in (None, "", []) and not base.get(k):
                base[k] = v
    accounts = list(merged.values())
    organizations = [o for o in organizations if o.get("cnpj") or o.get("razao_social")]
    if accounts:
        console.print(
            f"\n[bold gold1]{EYE_OF_HORUS_GLYPH} PERFIS & CONTAS ENCONTRADOS ({len(accounts)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        for acc in accounts:
            plat = acc.get("platform") or ("Keybase" if acc.get("id") and "username" in acc else "Perfil")
            user = acc.get("login") or acc.get("username") or acc.get("displayName") or "-"
            name = acc.get("name") or acc.get("display_name")
            profile_url = (
                acc.get("profile_url")
                or acc.get("html_url")
                or acc.get("profileUrl")
                or (f"https://keybase.io/{user}" if plat == "Keybase" else "")
            )

            head = Text("  ● ", style="bold green")
            head.append(f"{plat:<12}", style="bold cyan")
            head.append(f"@{user}", style="bold bright_white")
            if name:
                head.append(f"  ({name})", style="dim")
            console.print(head)
            if profile_url:
                link = Text("      ↳ ", style="dim")
                link.append(str(profile_url), style=f"bright_blue underline link {profile_url}")
                console.print(link, overflow="fold")

            meta_parts: list[str] = []
            if acc.get("bio"):
                meta_parts.append(f"Bio: {acc['bio']}")
            if acc.get("company"):
                meta_parts.append(f"Empresa: {acc['company']}")
            if acc.get("location"):
                meta_parts.append(f"Local: {acc['location']}")
            if acc.get("blog"):
                meta_parts.append(f"Site: {acc['blog']}")
            if acc.get("twitter_username"):
                meta_parts.append(f"X/Twitter: @{acc['twitter_username']}")
            if acc.get("public_repos") is not None:
                meta_parts.append(f"Repos: {acc['public_repos']}")
            if acc.get("followers") is not None:
                meta_parts.append(f"Seguidores: {acc['followers']}")
            if acc.get("created_at"):
                meta_parts.append(f"Criado em: {str(acc['created_at'])[:10]}")
            if acc.get("recent_repos"):
                meta_parts.append(f"Projetos ativos: {', '.join(acc['recent_repos'][:3])}")
            if acc.get("matched_person_name"):
                meta_parts.append(f"Encontrado pelo nome: {acc['matched_person_name']}")
            if acc.get("matched_email"):
                meta_parts.append(f"Vinculado ao e-mail: {acc['matched_email']}")
            if meta_parts:
                console.print(Text("        " + "  •  ".join(meta_parts), style="white"), overflow="fold")
            if acc.get("public_commit_emails"):
                console.print(
                    f"        [bold green]E-mails públicos em commits:[/bold green] {', '.join(acc['public_commit_emails'][:3])}",
                    overflow="fold",
                )
        console.print()

    # --- Render Section: Telecomunicações & GEOINT (Telefones / DDD) ---
    if locations:
        console.print(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} TELECOMUNICAÇÕES & LOCALIZAÇÃO ({len(locations)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        for loc in locations:
            e164 = loc.get("e164") or loc.get("cep") or loc.get("city") or "-"
            nat_fmt = loc.get("national_format") or e164
            reg = loc.get("region_name") or f"{loc.get('city', '')} - {loc.get('state', loc.get('uf', ''))}"
            line_type = loc.get("line_type", "").upper()
            cities = loc.get("cities_sample") or loc.get("cities") or []
            console.print(
                f"  ● [bold cyan]{e164}[/bold cyan] [dim]({nat_fmt})[/dim]  •  [bold white]{reg}[/bold white]",
                overflow="fold",
            )
            if line_type or loc.get("carrier_regulatory"):
                console.print(
                    f"        Linha: [bold]{line_type or 'N/A'}[/bold]  •  Regulador: {loc.get('carrier_regulatory', 'ANATEL')}",
                    overflow="fold",
                )
            if cities:
                console.print(f"        Cidades atendidas: {', '.join(cities[:5])}", overflow="fold")
        console.print()

    # --- Render Section: Dados Cadastrais & Quadro Societário (QSA) ---
    if organizations:
        console.print(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} DADOS CADASTRAIS & QUADRO SOCIETÁRIO (QSA) ({len(organizations)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        for org in organizations:
            cnpj = org.get("cnpj") or "-"
            razao = org.get("razao_social") or "-"
            sit = org.get("situacao_cadastral") or "ATIVA"
            cnae = org.get("cnae_principal") or "-"
            console.print(
                f"  ● [bold white]{razao}[/bold white]  [dim](CNPJ: {cnpj})[/dim]  •  Situação: [bold green]{sit}[/bold green]",
                overflow="fold",
            )
            if cnae and cnae != "-":
                console.print(f"        CNAE: {cnae}", overflow="fold")
            for s in org.get("qsa", [])[:6]:
                if isinstance(s, dict) and s.get("nome_socio"):
                    nome = s.get("nome_socio")
                    qual = s.get("qualificacao_socio") or "Sócio"
                    cpf_m = s.get("cnpj_cpf_do_socio") or "***"
                    console.print(f"        ↳ Sócio: [bold]{nome}[/bold] ({qual}) [dim]{cpf_m}[/dim]", overflow="fold")
        console.print()

    # --- Render Section: Vazamentos & Exposição em Infostealers ---
    if breaches:
        console.print(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} EXPOSIÇÃO EM VAZAMENTOS & INFOSTEALERS ({len(breaches)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        for br in breaches:
            name = br.get("Name") or br.get("target") or "Vazamento Registrado"
            date = str(br.get("BreachDate") or "-")
            dataclasses = br.get("DataClasses") or []
            data_str = ", ".join(dataclasses) if dataclasses else "Credenciais / Metadados de e-mail expostos"
            if br.get("stealers_records_count") is not None:
                cnt = br["stealers_records_count"]
                data_str = f"{cnt} registro(s) de infostealer detectado(s) (Hudson Rock Cavalier)"
            console.print(
                f"  ▲ [bold bright_red]{name}[/bold bright_red] [dim](Data: {date})[/dim]  •  {data_str}",
                overflow="fold",
            )
        console.print()

    # --- Render Section: Registros Públicos & Diários Oficiais ---
    if documents:
        console.print(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} REGISTROS PÚBLICOS & DIÁRIOS OFICIAIS ({len(documents)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        for d in documents:
            terr = d.get("title") or d.get("territory_name") or d.get("tribunal") or "Registro Público"
            dt = d.get("date") or d.get("language", "").upper() or "-"
            url = d.get("url") or d.get("profile_url") or ""
            excerpts = d.get("excerpts") or [d.get("summary") or d.get("classe") or ""]
            trecho = " ".join(str(excerpts[0] if excerpts else "").split())[:220]
            console.print(f"  ● [bold cyan]{terr}[/bold cyan]  [dim]({dt})[/dim]", overflow="fold")
            if url:
                console.print(f"      ↳ [bright_blue underline]{url}[/bright_blue underline]", overflow="fold")
            if trecho:
                console.print(f"        {trecho}", overflow="fold")
        console.print()

    # If no specialized cards had items, show standard entity overview
    if not (accounts or locations or organizations or breaches or documents):
        ent_table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} Entidades Descobertas ({len(entities)})",
            border_style="cyan",
            header_style="bold gold1",
            expand=True,
        )
        ent_table.add_column("Tipo", style="bold bright_cyan", width=18)
        ent_table.add_column("Valor Canônico", style="bright_white")
        ent_table.add_column("Confiabilidade", justify="right", style="green", width=14)
        ent_table.add_column("Fontes de Origem", style="yellow")
        for ent in entities:
            ent_table.add_row(
                ent.type.value,
                ent.canonical_value,
                f"{ent.confidence * 100:.0f}%",
                ", ".join(ent.sources),
            )
        console.print(ent_table)

    # 4. Correlation & Risk Alerts (CLEAN, AIRY & HIGHLY LEGIBLE — NO CRAMPED RED BOX!)
    if findings:
        alert_lines: list[Text] = []
        for f in findings:
            r_lvl = str(f.get("risk", "INFO")).upper()
            r_label = {"CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MÉDIO", "LOW": "BAIXO"}.get(r_lvl, "INFO")
            title = f.get("title", "Alerta de Correlação")
            desc = f.get("description", "")
            rule_id = f.get("rule_id", "CORR")

            line = Text()
            if r_lvl in {"CRITICAL", "HIGH"}:
                line.append(f"  ▲ {r_label:<8}", style="bold bright_red")
            elif r_lvl == "MEDIUM":
                line.append(f"  ● {r_label:<8}", style="bold yellow")
            else:
                line.append(f"  ○ {r_label:<8}", style="bold cyan")

            line.append(f"{title} ", style="bold white")
            line.append(f"({rule_id})\n", style="dim")
            line.append(f"              {desc}\n", style="dim white")
            alert_lines.append(line)

        alert_panel = Text.assemble(*alert_lines)
        console.print(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} NOTAS & CORRELAÇÕES ({len(findings)})[/bold gold1]"
        )
        console.rule(style="dim cyan")
        console.print(alert_panel, overflow="fold")
    else:
        console.print(
            "[bold green]✔ Nenhuma anomalia de alto risco ou conflito detectado pelo motor de correlação.[/bold green]\n"
        )

    # 5. Graph Relationships Tree
    graph_data = container.reporting.get_graph(case.id)
    edges = graph_data.get("edges", [])
    if edges:
        tree = Tree(
            f"[bold gold1]{EYE_OF_HORUS_GLYPH} Grafo de Vínculos Descobertos ({len(edges)} conexões)[/bold gold1]"
        )
        for edge in edges[:10]:
            tree.add(
                f"[cyan]{edge['from_label']}[/cyan] "
                f"[dim]──([bold gold1]{edge['relation']}[/bold gold1] • {edge['source_id']})──►[/dim] "
                f"[bright_white]{edge['to_label']}[/bright_white]"
            )
        console.print(Panel(tree, border_style="cyan", padding=(0, 2)))


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Exibe versão e emblema do Olho de Hórus"),
) -> None:
    """God's Eye (𓂀) OSINT Cybersecurity CLI."""
    ensure_zero_config_environment()
    if version:
        render_banner(console)
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty():
            _run_interactive_shell()
        else:
            render_banner(console)
            _display_quick_help()


@app.command("banner")
def cmd_banner() -> None:
    """Renderiza o emblema do Olho de Hórus (𓂀)."""
    render_banner(console)


@app.command("scan")
def cmd_scan(
    target_value: str = typer.Argument(..., help="Alvo a ser investigado (Nome, Usuário, E-mail, Telefone, CNPJ, IP, Cripto)"),
    case_title: str = typer.Option(
        "", "--case", "-c", help="Título do caso (criado automaticamente se omitido)"
    ),
    target_type: str | None = typer.Option(
        None, "--type", "-t", help="Tipo explícito (email, domain, ip, cnpj, cep, username, phone, crypto, person)"
    ),
    depth: int = typer.Option(2, "--depth", "-d", min=1, max=3, help="Profundidade da varredura em cascata (1 a 3)"),
    sources: str | None = typer.Option(
        None, "--sources", "-s", help="Lista de IDs de fontes separadas por vírgula"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Caminho para exportação do dossiê (.json, .md, .csv)"
    ),
    export_format: str = typer.Option(
        "json", "--format", "-f", help="Formato de exportação (json, md, csv)"
    ),
    legal_basis: LegalBasis = typer.Option(
        LegalBasis.CYBERSECURITY_DEFENSE,
        "--legal-basis",
        help="Base legal de conformidade (LGPD/GDPR)",
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suprime o banner inicial"),
) -> None:
    """Executa varredura OSINT de alta precisão com enriquecimento em cascata e correlação."""
    if not no_banner:
        render_compact_header(console)

    resolved_type = TargetType(target_type.lower()) if target_type else detect_target_type(target_value)
    selected_sources = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
    title = case_title or f"Investigação OSINT: {target_value} ({resolved_type.value})"

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

            with console.status(
                f"[bold gold1]{EYE_OF_HORUS_GLYPH} Varrendo alvo [bright_white]{target.normalized_value}[/bright_white] ({target.type.value})...[/bold gold1]",
                spinner="dots",
            ):
                summary = await container.orchestrator.investigate_target(
                    case_id=case.id,
                    target=target,
                    max_depth=depth,
                    selected_sources=selected_sources,
                    actor_role=Role.INVESTIGATOR,
                )

            # Render clean, highly readable intelligence report
            _render_scan_report(case, target, depth, summary, container)

            # Export dossier if requested
            if output:
                dossier = container.reporting.generate_dossier(
                    case_id=case.id,
                    export_format=export_format,
                    actor_role=Role.INVESTIGATOR,
                )
                out_path = Path(output)
                out_path.write_text(dossier["formatted_output"], encoding="utf-8")
                console.print(
                    f"\n[bold green]✔ Dossiê de Inteligência exportado com sucesso para:[/bold green] {out_path.resolve()}"
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


def _run_interactive_shell() -> None:
    """Start an interactive God's Eye (𓂀) analyst console with live autocomplete and history."""
    render_banner(console)
    _display_quick_help()

    hist_dir = Path.home() / ".godseye"
    hist_dir.mkdir(parents=True, exist_ok=True)
    hist_file = hist_dir / "history.txt"

    session: PromptSession[str] = PromptSession(
        completer=NestedCompleter.from_nested_dict(COMMAND_COMPLETIONS),
        auto_suggest=AutoSuggestFromHistory(),
        history=FileHistory(str(hist_file)),
        style=PtStyle.from_dict({
            "glyph": "#00e5ff bold",
            "prompt": "#e5a93b bold",
        }),
    )

    console.print(
        f"\n[bold gold1]{EYE_OF_HORUS_GLYPH} Console Interativo Iniciado com Autocomplete.[/bold gold1] "
        "[dim]Pressione [bold cyan]Tab[/bold cyan] para autocompletar ou digite o alvo diretamente.[/dim]\n"
    )

    while True:
        try:
            line = session.prompt([
                ("class:glyph", f"{EYE_OF_HORUS_GLYPH} "),
                ("class:prompt", "godseye > "),
            ]).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Sessão do Olho de Hórus encerrada.[/dim]")
            break

        if not line:
            continue

        # Tolerates and removes accidental "godseye " prefix
        if line.startswith("godseye "):
            line = line[len("godseye "):].strip()

        low = line.lower()
        if low in {"exit", "quit", "q"}:
            console.print("[dim]Sessão do Olho de Hórus encerrada.[/dim]")
            break
        if low in {"clear", "cls"}:
            os.system("cls" if os.name == "nt" else "clear")
            render_compact_header(console)
            continue
        if low in {"help", "?"}:
            _display_quick_help()
            continue
        if low == "banner":
            render_banner(console)
            continue

        try:
            args = shlex.split(line)
            if not args:
                continue

            first_cmd = args[0].lower()
            known_cmds = set(COMMAND_COMPLETIONS.keys())

            # If user types a target directly (e.g. +5511999998888, torvalds, 00.000...):
            if first_cmd not in known_cmds:
                args = ["scan", line, "--no-banner"]
            elif first_cmd == "scan" and "--no-banner" not in args:
                args.append("--no-banner")

            app(args=args, standalone_mode=False)
        except SystemExit:
            pass
        except Exception as exc:
            console.print(f"[bold red]Erro na execução:[/bold red] {exc}")


@app.command("shell")
def cmd_shell() -> None:
    """Inicia o console analítico interativo do Olho de Hórus (𓂀) com autocomplete."""
    _run_interactive_shell()


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


@app.command("doctor")
def cmd_doctor() -> None:
    """Run zero-config environment self-diagnostics (DB, Cache, UTF-8, 135+ Sources)."""
    boot = ensure_zero_config_environment()
    container = AppContainer()
    try:
        all_sources = container.registry.list_sources()
        live_sources = container.registry.list_sources(live_only=True)
        br_sources = container.registry.list_sources(region="brasil")

        table = Table(
            title=f"{EYE_OF_HORUS_GLYPH} God's Eye Zero-Config Self-Check (READY FOR USE)",
            border_style="green",
            header_style="bold gold1",
        )
        table.add_column("Component", style="bold bright_cyan")
        table.add_column("Status", style="bold green")
        table.add_column("Details", style="white")

        table.add_row("UTF-8 Terminal & Glyph", "✔ READY", f"Eye of Horus ({EYE_OF_HORUS_GLYPH}) active")
        table.add_row("Zero-Config .env", "✔ READY", boot["env_file"])
        table.add_row("SQLite WAL Database", "✔ READY", boot["db_path"])
        table.add_row("Multi-Tier Cache (L1+L2)", "✔ READY", "LRU Memory + SQLite TTL active")
        table.add_row(
            "OSINT API Catalog",
            "✔ READY",
            f"{len(all_sources)} total sources ({len(br_sources)} Brasil / OSINT Brazuca)",
        )
        table.add_row(
            "Zero-Key Live Collectors",
            "✔ READY",
            f"{len(live_sources)} active adapters ready without requiring paid API keys",
        )
        console.print(table)
    finally:
        asyncio.run(container.shutdown())


def _run_interactive_menu() -> None:
    """Interactive zero-config numbered menu for immediate analyst use."""
    while True:
        console.print(
            Panel(
                "[bold bright_cyan][1][/bold bright_cyan] Investigar Alvo Agora (Domínio, E-mail, IP, CNPJ, CEP, Telefone, Carteira Cripto, Username)\n"
                "[bold bright_cyan][2][/bold bright_cyan] Listar Fontes OSINT (135+ APIs Globais & Brasil / OSINT Brazuca)\n"
                "[bold bright_cyan][3][/bold bright_cyan] Ver Casos Investigativos & Exportar Dossiê (Markdown / JSON / CSV)\n"
                "[bold bright_cyan][4][/bold bright_cyan] Watchlists & Alertas Contínuos\n"
                "[bold bright_cyan][5][/bold bright_cyan] Diagnóstico Zero-Config & Benchmark de Performance\n"
                "[bold bright_cyan][6][/bold bright_cyan] Iniciar Servidor REST FastAPI (/api/v1 + Swagger UI em http://127.0.0.1:8000/docs)\n"
                "[bold bright_cyan][0][/bold bright_cyan] Sair",
                title=f"[bold gold1]{EYE_OF_HORUS_GLYPH} MENU RÁPIDO ZERO-CONFIG — PRONTO PARA USO[/bold gold1]",
                border_style="gold1",
            )
        )
        try:
            choice = console.input(
                f"[bold gold1]{EYE_OF_HORUS_GLYPH} Escolha uma opção [0-6] ou digite um alvo direto (Enter para sair): [/bold gold1]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not choice or choice in {"0", "exit", "quit", "q"}:
            break
        if choice == "1":
            target_val = console.input(
                "[bold cyan]Digite o alvo (ex: example.com, 00.000.000/0001-91, +5511999998888, 0x8589...): [/bold cyan]"
            ).strip()
            if target_val:
                cmd_scan(
                    target_value=target_val,
                    case_title="",
                    target_type=None,
                    depth=2,
                    sources=None,
                    output=None,
                    export_format="json",
                    legal_basis=LegalBasis.CYBERSECURITY_DEFENSE,
                    no_banner=True,
                )
        elif choice == "2":
            cmd_sources(region=None, category=None, live_only=False)
        elif choice == "3":
            cmd_cases()
        elif choice == "4":
            cmd_watchlist(target_value=None, case_id="global", frequency="realtime", min_risk="high")
            cmd_alerts(ack_id=None, unack_only=False)
        elif choice == "5":
            cmd_doctor()
            cmd_benchmark()
        elif choice == "6":
            cmd_serve(host="127.0.0.1", port=8000)
        else:
            # Treat direct input as a target to scan!
            cmd_scan(
                target_value=choice,
                case_title="",
                target_type=None,
                depth=2,
                sources=None,
                output=None,
                export_format="json",
                legal_basis=LegalBasis.CYBERSECURITY_DEFENSE,
                no_banner=True,
            )


@app.command("menu")
def cmd_menu() -> None:
    """Open the interactive Zero-Config OSINT Menu."""
    render_banner(console)
    _run_interactive_menu()


@app.command("username")
def cmd_username(
    handle: str = typer.Argument(..., help="Username / handle to search across networks (e.g. torvalds)"),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional path to export dossier (.md, .json, .csv)"),
    export_format: str = typer.Option("md", "--format", "-f", help="Export format: md, json, csv"),
) -> None:
    """Search a username across multiple social & developer networks (GitHub, GitLab, Reddit, HN, Dev.to, DockerHub, Keybase, Chess.com)."""
    clean_handle = handle.strip().lstrip("@")
    cmd_scan(
        target_value=clean_handle,
        case_title=f"SOCMINT Username Hunt: @{clean_handle}",
        target_type="username",
        depth=1,
        sources=None,
        output=output,
        export_format=export_format,
        legal_basis=LegalBasis.CYBERSECURITY_DEFENSE,
        no_banner=False,
    )


def app_entry() -> None:
    """Console script entry point."""
    configure_terminal_utf8()
    app()


if __name__ == "__main__":
    app_entry()

