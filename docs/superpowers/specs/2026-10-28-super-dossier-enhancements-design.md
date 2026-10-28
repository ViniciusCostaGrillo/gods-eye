# Design Spec: Super-Dossiê OSINT (Filtros Anti-Homônimos, Exportação HTML Interativa, Placas Veiculares e Navegação Interativa)

- **Data:** 2026-10-28
- **Projeto:** God's Eye (`𓂀`) — `C:\God's Eye`
- **Escopo:** 
  1. Filtros contextuais anti-homônimos (`--uf`, `--city`, `--context`) nas buscas de Pessoa/CPF.
  2. Exportador de Dossiê Executivo em HTML Interativo (`--format html`) com grafo visual embutido.
  3. Extrator e enriquecimento de Placas Veiculares (padrão cinza e Mercosul) associadas a alvos.
  4. Modo interativo de pivô pós-scan com 1 clique/número (`[1] Pivotar em empresa...`, `[2] Abrir processos...`).

---

## 1. Intenção e Motivação

Com os coletores profundos e o novo dossiê já operacionais, o fluxo de investigação do analista precisa ser refinado:
- Permitir restringir buscas de nomes comuns por UF/município para eliminar homônimos irrelevantes.
- Permitir compartilhar dossiês investigativos completos fora do terminal em formato HTML estilizável e interativo.
- Descobrir automaticamente veículos/placas citados em editais, leilões, autos e diários oficiais.
- Permitir pivotar instantaneamente em empresas ou processos descobertos no scan interativo sem precisar copiar/colar comandos.

---

## 2. Especificação Técnica dos 4 Módulos

### 2.1 Filtros Anti-Homônimos (`godseye/collectors/expansion_sources.py` & `godseye/cli/main.py`)
- Adicionar flags opcionais no CLI: `--uf` (ex: `SP`) e `--city` (ex: `Campinas`).
- Passar os filtros no `Target.metadata` para os coletores de pessoa.
- Ao pesquisar no DuckDuckGo / Querido Diário, adicionar a restrição geográfica à query (`"{nome}" {uf} {city}`).
- Atribuir score de relevância ponderado: resultados que contenham a UF e/ou município filtrado recebem prioridade máxima e destacam a tag `[Filtro Geográfico Confirmado]`.

### 2.2 Exportador de Dossiê HTML Interativo (`godseye/services/reporting.py`)
- Adicionar suporte a `format == "html"` em `ReportingService.generate_dossier`.
- O HTML gerado deve ser:
  - 100% autônomo (CSS moderno dark mode / neon cyber, fontes do sistema, responsivo).
  - Incluir a **Ficha Consolidada do Alvo**, tabelas estilizadas de empresas, QSA, processos judiciais, contatos e vazamentos.
  - Renderizar o grafo de vínculos em Mermaid.js embutido com SVG interativo.

### 2.3 Detecção e Extrator de Placas Veiculares (`godseye/collectors/brazil_sources.py`)
- Criar `is_valid_vehicle_plate(raw: str) -> bool`:
  - Padrão Antigo: `[A-Z]{3}-\d{4}` ou `[A-Z]{3}\d{4}` (ex: `ABC-1234`).
  - Padrão Mercosul: `[A-Z]{3}\d[A-Z]\d{2}` (ex: `ABC1D23`).
- Adicionar detecção de placas em `extract_brazil_entities_from_text`.
- Criar novo coletor `BrasilVehiclePlateCollector` (`accepts = {TargetType.VEHICLE_PLATE}`):
  - Identifica o padrão (Antigo ou Mercosul), UF provável de emissão (se padrão antigo de acordo com a tabela DENATRAN) e busca menções em diários/leilões públicos.

### 2.4 Menu Interativo de Ação Pós-Scan (`godseye/cli/main.py`)
- No modo interativo (`godseye` sem argumentos ou no terminal TTY), ao término da exibição do relatório:
  - Se houver empresas ou processos descobertos, apresentar opções rápidas:
    - `[1..N]` Investigar automaticamente CNPJ descoberto (pivô instantâneo sem digitar comando).
    - `[P]` Abrir links dos processos judiciais no navegador padrão.
    - `[H]` Exportar imediatamente o dossiê para `dossie_<alvo>.html`.
    - `[Enter]` Voltar ao prompt interativo.

---

## 3. Plano de Testes (TDD)
- Teste de validação e extração de placas veiculares (Antigo e Mercosul).
- Teste de geração de dossiê em formato HTML (estrutura de tags, ficha consolidada e grafo).
- Teste de aplicação de filtros geográficos na busca de pessoa.
- Teste de regressão completo da suíte.
