# Super-Dossier Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement anti-homonym filters, standalone interactive HTML dossier export, vehicle plate extraction & OSINT collector, and post-scan interactive pivoting menu.

**Architecture:**
1. Task 1: Vehicle plate detection (`is_valid_vehicle_plate`), extraction in `extract_brazil_entities_from_text`, and `BrasilVehiclePlateCollector` in `godseye/collectors/brazil_sources.py`.
2. Task 2: Standalone HTML Dossier Generator in `godseye/services/reporting.py`.
3. Task 3: Anti-homonym filters (`--uf`, `--city`) in Person collectors and CLI arguments.
4. Task 4: Interactive post-scan action menu in `godseye/cli/main.py`.
5. Task 5: Full test suite verification & live smoke test.

---

### Task 1: Vehicle Plate Regex, Extraction & BrasilVehiclePlateCollector

**Files:**
- Modify: `godseye/collectors/brazil_sources.py`
- Modify: `godseye/collectors/registry.py`
- Test: `tests/test_vehicle_plate_collector.py`

- [ ] **Step 1: Write failing test for vehicle plate detection & collector**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement vehicle plate extraction and `BrasilVehiclePlateCollector`**
- [ ] **Step 4: Run test to verify it passes**

### Task 2: Standalone Interactive HTML Dossier Export

**Files:**
- Modify: `godseye/services/reporting.py`
- Test: `tests/test_html_dossier_export.py`

- [ ] **Step 1: Write failing test for HTML export generation**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement HTML template generation with embedded CSS & Mermaid**
- [ ] **Step 4: Run test to verify it passes**

### Task 3: Anti-Homonym Filters (`--uf`, `--city`)

**Files:**
- Modify: `godseye/collectors/expansion_sources.py`
- Modify: `godseye/cli/main.py`
- Test: `tests/test_anti_homonym_filters.py`

- [ ] **Step 1: Write failing test verifying filter passed to collector queries**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement `--uf` and `--city` handling and contextual scoring**
- [ ] **Step 4: Run test to verify it passes**

### Task 4: Post-Scan Quick Pivoting Interactive Action Menu

**Files:**
- Modify: `godseye/cli/main.py`
- Test: `tests/test_post_scan_menu.py`

- [ ] **Step 1: Write failing test for post-scan interactive helper**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement interactive menu in CLI**
- [ ] **Step 4: Run test to verify it passes**

### Task 5: Full Integration & Regression Suite Verification

- [ ] **Step 1: Run full pytest suite across all modules**
- [ ] **Step 2: Live scan smoke tests (HTML export + vehicle plate)**
