# Deep Brazilian OSINT & Consolidated CLI Dossier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform God's Eye into a high-utility, 100% free OSINT engine and CLI dossier that extracts real civil identities, linked companies (QSA/CNPJ), complete street addresses, judicial processes (CNJ format), and contacts for Person Name, CPF, Phone, and CNPJ targets without synthetic filler.

**Architecture:** 
1. Build a resilient multi-source entity extraction helper (`search_public_web_records` & `extract_brazil_entities_from_text`) in `godseye/collectors/brazil_sources.py` decoding clean URLs and validating CNPJ Modulo-11 / CNJ process structures.
2. Upgrade `BrasilApiCnpjCollector` with multi-provider fallbacks (`publica.cnpj.ws`, `receitaws`) extracting complete street address, corporate phones/emails, and QSA partners.
3. Enhance `BrasilCpfOsintCollector`, `PublicPersonAndLeakCollector`, and `PhoneOsintCollector` to extract and yield discovered CNPJs, civil names, and judicial lawsuits.
4. Upgrade `DataJudCnjCollector` to accept `TargetType.PERSON` and `TargetType.CNPJ` and decode CNJ metadata instead of returning static stubs.
5. Upgrade `InvestigationOrchestrator` cascading logic to automatically pivot discovered CNPJs, Names, and Process targets.
6. Redesign `_render_scan_report` in `godseye/cli/main.py` with an executive `FICHA CONSOLIDADA DO ALVO` and structured detailed cards without filler.

**Tech Stack:** Python 3.11+, Typer, Rich, HTTPX, Pydantic, SQLite WAL, Pytest, Pytest-Asyncio.

**Spec:** [docs/superpowers/specs/2026-10-28-deep-osint-cli-dossier-design.md](file:///C:/God's%20Eye/docs/superpowers/specs/2026-10-28-deep-osint-cli-dossier-design.md)

## Global Constraints

- 100% free public sources only; no mandatory paid API keys or commercial credit bureaus.
- Maintain LGPD data minimization and raw evidence SHA-256 provenance for all observations.
- Never emit synthetic dummy records ("EMPRESA BRASILEIRA S.A.", "Compliance Check: sem restrições") in live CLI scan results.
- Never truncate URLs, CNJ process numbers, company names, or addresses in the terminal report.
- Maintain full test suite pass on all existing and new tests.

## Review Focus

- Malformed or invalid CNPJ strings extracted from messy HTML: must pass Modulo-11 verification before being emitted as `discovered_cnpj`.
- DuckDuckGo / HTML redirect URLs (`//duckduckgo.com/l/?uddg=...`): must be unquoted to real clean destination URLs.
- Person names with prepositions/particles ("de", "da", "dos", "e"): name normalization must preserve casing conventions and avoid false positive dictionary words.
- CNJ process numbers across different judicial branches: tribunal routing must accurately map court codes (`8.26` -> TJSP, `4.01` -> TRF1, `5.02` -> TRT2).
- Zero observations found for a category: section card must cleanly omit itself rather than displaying empty or filler boxes.

---

### Task 1: Brazilian Entity Extraction Engine & CNPJ Multi-Provider Enrichment

**Files:**
- Modify: `godseye/collectors/brazil_sources.py`
- Modify: `godseye/collectors/base.py`
- Test: `tests/test_brazil_extraction_and_cnpj.py`

**Interfaces:**
- Produces: `is_valid_cnpj(raw: str) -> bool`
- Produces: `decode_duckduckgo_url(raw_url: str) -> str`
- Produces: `extract_brazil_entities_from_text(text: str) -> dict[str, list[Any]]`
- Produces: `BrasilApiCnpjCollector.collect` yielding complete street address, phone, email, and QSA observations with fallbacks to `publica.cnpj.ws` and `receitaws`.

- [ ] **Step 1: Write failing tests for CNPJ Mod-11 validation, DDG URL decoding, text extraction, and enriched CNPJ fields**

```python
# tests/test_brazil_extraction_and_cnpj.py
from godseye.collectors.brazil_sources import (
    is_valid_cnpj,
    decode_duckduckgo_url,
    extract_brazil_entities_from_text,
    BrasilApiCnpjCollector,
)

def test_is_valid_cnpj():
    assert is_valid_cnpj("00.000.000/0001-91") is True  # Banco do Brasil
    assert is_valid_cnpj("11.111.111/1111-11") is False
    assert is_valid_cnpj("00000000000191") is True

def test_decode_duckduckgo_url():
    ddg = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fqueridodiario.ok.org.br%2Fgazettes%2F123&rut=1"
    assert decode_duckduckgo_url(ddg) == "https://queridodiario.ok.org.br/gazettes/123"
    assert decode_duckduckgo_url("https://example.com") == "https://example.com"

def test_extract_brazil_entities_from_text():
    sample = (
        "O socio Joao da Silva, portador do CPF 123.456.789-00, da empresa "
        "ABC LTDA CNPJ 00.000.000/0001-91, responde ao processo 0001234-56.2024.8.26.0100 "
        "no TJSP. Contato: (11) 98765-4321, CEP 01001-000."
    )
    res = extract_brazil_entities_from_text(sample)
    assert "00.000.000/0001-91" in res["cnpjs"]
    assert "0001234-56.2024.8.26.0100" in res["processes"]
    assert "01001-000" in res["ceps"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_brazil_extraction_and_cnpj.py -v`
Expected: FAIL with missing functions / imports

- [ ] **Step 3: Implement functions and enriched CNPJ collector in `godseye/collectors/brazil_sources.py`**

Implement:
- `is_valid_cnpj(raw: str) -> bool` using Modulo-11 algorithm.
- `decode_duckduckgo_url(url: str) -> str` using `urllib.parse`.
- `extract_brazil_entities_from_text(text: str) -> dict[str, list[Any]]`.
- Update `BrasilApiCnpjCollector.collect` with multi-provider fallback (`publica.cnpj.ws/cnpj/{cnpj}` and `receitaws.com.br/v1/cnpj/{cnpj}`), extracting `logradouro`, `numero`, `bairro`, `municipio`, `uf`, `cep`, `endereco_completo`, `telefones`, `email`, and complete `qsa`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_brazil_extraction_and_cnpj.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add godseye/collectors/brazil_sources.py tests/test_brazil_extraction_and_cnpj.py
git commit -m "feat: add brazil entity extraction and enriched multi-provider CNPJ collector"
```

---

### Task 2: Public Record Discovery for CPF, Person Names & Phones

**Files:**
- Modify: `godseye/collectors/brazil_sources.py` (update `BrasilCpfOsintCollector`)
- Modify: `godseye/collectors/expansion_sources.py` (update `PublicPersonAndLeakCollector` and `PhoneOsintCollector`)
- Test: `tests/test_person_cpf_phone_discovery.py`

**Interfaces:**
- Produces: `BrasilCpfOsintCollector.collect` emitting discovered person names, CNPJs, processes, and mentions.
- Produces: `PublicPersonAndLeakCollector.collect` emitting discovered CNPJs (QSA), legal cases, and addresses for `TargetType.PERSON`.
- Produces: `PhoneOsintCollector.collect` performing public web search and emitting discovered CNPJs and civil names linked to phone numbers.

- [ ] **Step 1: Write failing tests for CPF, Person, and Phone discovery**

```python
# tests/test_person_cpf_phone_discovery.py
import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import EntityType, TargetType
from godseye.domain.models import Target

@pytest.mark.asyncio
async def test_cpf_discovery_observations(container: AppContainer):
    cpf_adapter = container.registry.get_adapter("brasil_cpf")
    assert cpf_adapter is not None
    target = Target(value="529.982.247-25", type=TargetType.PERSON)
    obs_list = [obs async for obs in cpf_adapter.collect(target)]
    types = {obs.entity_type for obs in obs_list}
    assert EntityType.PERSON in types

@pytest.mark.asyncio
async def test_person_name_discovery_observations(container: AppContainer):
    adapter = container.registry.get_adapter("person_and_leak_osint")
    assert adapter is not None
    target = Target(value="Silvio Santos", type=TargetType.PERSON)
    obs_list = [obs async for obs in adapter.collect(target)]
    assert len(obs_list) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_person_cpf_phone_discovery.py -v`
Expected: FAIL or missing features

- [ ] **Step 3: Implement multi-source discovery in `BrasilCpfOsintCollector`, `PublicPersonAndLeakCollector`, and `PhoneOsintCollector`**

- In `BrasilCpfOsintCollector`: use targeted search queries for QSA and processes, extracting `discovered_cnpjs` and `discovered_processes`.
- In `PublicPersonAndLeakCollector`: for `TargetType.PERSON`, run targeted queries for companies (`sócio`, `CNPJ`) and legal cases (`processo`, `tribunal`), extracting CNPJs and lawsuits.
- In `PhoneOsintCollector`: search national phone formats to detect commercial registrations (CNPJ) and contact mentions.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_person_cpf_phone_discovery.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add godseye/collectors/brazil_sources.py godseye/collectors/expansion_sources.py tests/test_person_cpf_phone_discovery.py
git commit -m "feat: enhance public entity discovery for CPF, person names, and phone targets"
```

---

### Task 3: Real Judicial Case Collector (`DataJudCnjCollector`)

**Files:**
- Modify: `godseye/collectors/brazil_sources.py`
- Test: `tests/test_datajud_collector.py`

**Interfaces:**
- Consumes: CNJ process number format `NNNNNNN-NN.NNNN.N.NN.NNNN`
- Produces: `parse_cnj_process_number(cnj: str) -> dict[str, str]`
- Produces: `DataJudCnjCollector` accepting `{TargetType.PROCESSO, TargetType.CNPJ, TargetType.PERSON}` and returning verified court, class, and process details without static placeholder stubs.

- [ ] **Step 1: Write failing test for CNJ number decoding and DataJud collector**

```python
# tests/test_datajud_collector.py
import pytest
from godseye.collectors.brazil_sources import parse_cnj_process_number, DataJudCnjCollector
from godseye.domain.enums import TargetType
from godseye.domain.models import Target

def test_parse_cnj_process_number():
    info = parse_cnj_process_number("0001234-56.2024.8.26.0100")
    assert info["is_valid"] is True
    assert info["ano"] == "2024"
    assert info["ramo"] == "Justiça Estadual"
    assert info["tribunal"] == "TJSP"

@pytest.mark.asyncio
async def test_datajud_collector_accepts_person_and_cnpj(container):
    adapter = container.registry.get_adapter("datajud_cnj")
    assert TargetType.PERSON in adapter.accepts
    assert TargetType.CNPJ in adapter.accepts
    assert TargetType.PROCESSO in adapter.accepts
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_datajud_collector.py -v`
Expected: FAIL with `parse_cnj_process_number` not found or accepts missing `TargetType.PERSON`

- [ ] **Step 3: Implement `parse_cnj_process_number` and update `DataJudCnjCollector` in `godseye/collectors/brazil_sources.py`**

- Map CNJ court codes (`8.26` -> TJSP, `8.19` -> TJRJ, `4.01..4.06` -> TRF1..TRF6, `5.01..5.24` -> TRT).
- Decode process metadata and search public records for lawsuits.
- Remove synthetic static placeholder stub when no cases exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_datajud_collector.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add godseye/collectors/brazil_sources.py tests/test_datajud_collector.py
git commit -m "feat: implement CNJ process decoding and real judicial search in DataJud collector"
```

---

### Task 4: Cascading Multi-Hop Discovery & Correlation for Discovered Entities

**Files:**
- Modify: `godseye/services/orchestrator.py:267-360`
- Modify: `godseye/services/correlation.py`
- Test: `tests/test_cascading_brazil_entities.py`

**Interfaces:**
- Consumes: `RawObservation.raw_payload` with `discovered_cnpj`, `discovered_person_name`, or `discovered_processes`
- Produces: `InvestigationOrchestrator._derive_cascading_targets` spawning secondary hops:
  - `discovered_cnpj` -> `Target(type=TargetType.CNPJ)`
  - `discovered_person_name` -> `Target(type=TargetType.PERSON)`
  - `discovered_processes` -> `Target(type=TargetType.PROCESSO)`

- [ ] **Step 1: Write failing test for cascading CNPJ and person discovery**

```python
# tests/test_cascading_brazil_entities.py
import pytest
from godseye.api.app import AppContainer
from godseye.domain.enums import Role, TargetType

@pytest.mark.asyncio
async def test_cascading_person_to_cnpj_pipeline(container: AppContainer):
    case = container.case_service.create_case(title="Test Cascading Person to CNPJ")
    target = container.case_service.add_target(case.id, "529.982.247-25", TargetType.PERSON)
    summary = await container.orchestrator.investigate_target(
        case_id=case.id,
        target=target,
        max_depth=2,
        actor_role=Role.INVESTIGATOR,
    )
    targets = container.repo.list_targets(case.id)
    target_types = {t.type for t in targets}
    assert TargetType.PERSON in target_types
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_cascading_brazil_entities.py -v`
Expected: Check current behavior and test output

- [ ] **Step 3: Update `_derive_cascading_targets` in `godseye/services/orchestrator.py`**

Add derivation rules for:
- Discovered CNPJs from person, CPF, and phone observations.
- Discovered full names from CPF and phone observations.
- Connect relationships in `EntityRelationship` store.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_cascading_brazil_entities.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add godseye/services/orchestrator.py tests/test_cascading_brazil_entities.py
git commit -m "feat: cascade discovered CNPJs, names, and legal processes in investigation orchestrator"
```

---

### Task 5: Redesigned Consolidated Intelligence Dossier Layout in CLI

**Files:**
- Modify: `godseye/cli/main.py:230-610`
- Test: `tests/test_cli_dossier_layout.py`

**Interfaces:**
- Produces: `_render_scan_report` rendering:
  1. Header Card (Operation Metadata)
  2. `FICHA CONSOLIDADA DO ALVO (RESUMO EXECUTIVO)` Panel
  3. `EMPRESAS & QUADRO SOCIETÁRIO (QSA / RECEITA FEDERAL)` (Complete address, phones, capital, partners)
  4. `PROCESSOS JUDICIAIS & TRIBUNAIS (CNJ)`
  5. `DIÁRIOS OFICIAIS & PUBLICAÇÕES PÚBLICAS`
  6. `ENDEREÇOS & TELECOMUNICAÇÕES VINCULADAS`
  7. `PERFIS DIGITAIS, REDES SOCIAIS & VAZAMENTOS`
  8. Graph and Notes, with zero synthetic filler cards.

- [ ] **Step 1: Write failing test verifying consolidated dossier components in CLI output**

```python
# tests/test_cli_dossier_layout.py
from typer.testing import CliRunner
from godseye.cli.main import app

runner = CliRunner()

def test_scan_cli_renders_consolidated_card(tmp_path, monkeypatch):
    monkeypatch.setenv("GODSEYE_DB_PATH", str(tmp_path / "test_cli_dossier.db"))
    res = runner.invoke(app, ["scan", "00.000.000/0001-91", "--depth", "1", "--sources", "brasil_cnpj"])
    assert res.exit_code == 0
    assert "FICHA CONSOLIDADA DO ALVO" in res.stdout or "EMPRESAS" in res.stdout
    assert "Compliance Check CEIS/CNEP: Sem restrições" not in res.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.\.venv\Scripts\pytest.exe tests/test_cli_dossier_layout.py -v`
Expected: FAIL

- [ ] **Step 3: Redesign `_render_scan_report` in `godseye/cli/main.py`**

- Build and render `FICHA CONSOLIDADA DO ALVO` with Name, CPF/CNPJ, confirmed full addresses, phones, and counts.
- Add enriched company card showing complete address (`logradouro`, `numero`, `bairro`, `cep`, `municipio`), corporate phones, and QSA.
- Clean up filler and suppress synthetic observations from display.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\.venv\Scripts\pytest.exe tests/test_cli_dossier_layout.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add godseye/cli/main.py tests/test_cli_dossier_layout.py
git commit -m "feat: redesign CLI intelligence dossier with executive summary and enriched cards"
```

---

### Task 6: Full Integration & Regression Suite Verification

**Files:**
- Modify: `tests/`
- Test: Entire test suite (`pytest`)

- [ ] **Step 1: Run the full Pytest test suite**

Run: `.\.venv\Scripts\pytest.exe -v`
Expected: 100% PASS

- [ ] **Step 2: Run manual CLI verification with real targets**

Run: `.\.venv\Scripts\python.exe -m godseye scan "Linus Torvalds" --depth 1`
Run: `.\.venv\Scripts\python.exe -m godseye scan "00.000.000/0001-91" --depth 1`
Expected: Clean, airy dossier layout with verified data and zero filler.

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: complete deep OSINT and CLI dossier redesign with green test suite"
```
