# Design Spec: Investigação OSINT Profunda (100% Gratuita) e Novo Layout de Dossiê no CLI

- **Data:** 2026-10-28
- **Projeto:** God's Eye (`𓂀`) — `C:\God's Eye`
- **Escopo:** Redesenho dos coletores brasileiros (`CPF`, `Nome/Pessoa`, `Telefone`, `CNPJ`, `Processos/DataJud`), pivô automático em cascata no `InvestigationOrchestrator` e novo layout de **Ficha Investigativa Consolidada** no CLI (`godseye/cli/main.py`).

---

## 1. Intenção e Motivação (The Why)

Hoje, ao pesquisar um **Nome**, **CPF** ou **Telefone** no God's Eye, a experiência ainda traz resultados superficiais ou genéricos:
- Para **CPF**, destaca apenas que o número é matematicamente válido (Módulo 11) e qual é a região fiscal, com busca limitada.
- Para **Nome (`TargetType.PERSON`)**, consulta apenas GitHub, Wikipedia e até 3 resultados do Querido Diário — ignorando **empresas no nome da pessoa (QSA/CNPJ)**, **processos judiciais** e **endereços/vínculos em documentos públicos**.
- Para **Telefone (`TargetType.PHONE`)**, mostra apenas o estado/DDD e uma lista genérica de cidades da BrasilAPI, sem buscar empresas (CNPJs), editais ou registros públicos que utilizam aquele telefone.
- O coletor **DataJud (`DataJudCnjCollector`)** retorna apenas um registro estático (`"DataJud/CNJ Index: <alvo>"`) sem realizar busca real nem aceitar pessoas/CPFs, e o **Portal da Transparência (`PortalTransparenciaSanctionsCollector`)** emite um documento genérico de `"Compliance Check"` mesmo quando nada foi encontrado.

O objetivo deste projeto é tornar o God's Eye **realmente útil em investigações reais**, utilizando **100% fontes públicas e gratuitas**, cruzando dados automaticamente em cascata e apresentando no CLI um dossiê claro, completo e livre de ruído genérico.

---

## 2. Objetivos, Não-Objetivos e Anti-Objetivos

### Objetivos (Goals)
1. **Descoberta Multi-Fonte 100% Gratuita para Pessoa, CPF e Telefone**:
   - Extrair de múltiplas fontes abertas (Querido Diário, DuckDuckGo HTML/Lite com decodificação real de URLs `uddg`, buscas web estruturadas para QSA/empresas/processos e APIs públicas) entidades concretas:
     - **Nomes Civis Completos** vinculados a um CPF ou Telefone.
     - **CNPJs (`XX.XXX.XXX/XXXX-XX`)** de empresas das quais a pessoa/CPF é sócia/administradora (QSA) ou às quais o telefone pertence.
     - **Processos Judiciais (padrão CNJ `NNNNNNN-NN.NNNN.N.NN.NNNN`)**, identificando tribunal (`TJSP`, `TJRJ`, `TRF`, `TRT`, `STF`, `STJ`, etc.), partes/contexto e link da publicação.
     - **Endereços, CEPs e Contatos (Telefones/E-mails)** expostos em atos oficiais, registros societários e editais públicos.
2. **Enriquecimento Completo de CNPJ (Receita Federal Gratuita)**:
   - Atualizar o `BrasilApiCnpjCollector` para consultar `BrasilAPI` (`https://brasilapi.com.br/api/cnpj/v1/{cnpj}`) com fallback automático para a API pública gratuita `CNPJ.ws` (`https://publica.cnpj.ws/cnpj/{cnpj}`) e `ReceitaWS` (`https://receitaws.com.br/v1/cnpj/{cnpj}`), extraindo:
     - Razão Social, Nome Fantasia, Situação Cadastral, Data de Abertura, CNAE Principal, Capital Social.
     - **Endereço Completo da Empresa**: Logradouro (rua/avenida), Número, Complemento, Bairro, Município, UF e CEP.
     - **Contatos Cadastrais da Empresa**: Telefones (DDD + número) e E-mail corporativo registrados na Receita Federal.
     - **Quadro de Sócios e Administradores (QSA)**: Nome do sócio, qualificação e faixa etária / documento mascarado.
3. **Pivô Automático em Cascata (`InvestigationOrchestrator`)**:
   - Quando uma busca por **CPF**, **Nome** ou **Telefone** encontrar **CNPJs**, o orquestrador pivota automaticamente para `TargetType.CNPJ` no salto seguinte, puxando toda a ficha da empresa (endereço completo, telefones, QSA) e vinculando ao alvo original.
   - Quando uma busca por **CPF** ou **Telefone** descobrir o **Nome Civil** do titular, o orquestrador pivota para `TargetType.PERSON` para buscar as empresas, processos e perfis daquela pessoa.
   - Quando uma busca por **CNPJ** retornar endereço/CEP e sócios, o orquestrador enriquece o CEP e registra as relações no grafo.
4. **Coletor Real de Processos Judiciais (`DataJudCnjCollector`)**:
   - Aceitar `TargetType.PROCESSO`, `TargetType.CNPJ` e `TargetType.PERSON`.
   - Consultar a API Pública do DataJud/CNJ (quando houver número CNJ e chave pública/configurada) **e** realizar busca pública indexada de processos judiciais e diários de justiça, extraindo número CNJ unificado, tribunal/órgão julgador, assunto/resumo e URL de verificação.
   - Nunca emitir registros estáticos/vazios quando nenhum processo for localizado.
5. **Novo Layout de Dossiê no CLI (`_render_scan_report` em `godseye/cli/main.py`)**:
   - Exibir logo abaixo do cabeçalho uma **Ficha Consolidada do Alvo (Resumo Executivo)** reunindo em um único painel claro:
     - **Identidade / Titular**: Nome(s) civil(is) identificado(s), CPF/CNPJ e Região Fiscal (apenas como metadado secundário).
     - **Empresas no Nome / Vínculos Societários**: Quantidade e lista direta de Razão Social + CNPJ + Papel (Sócio/Titular).
     - **Endereços Localizados**: Endereços completos (Rua, Número, Bairro, Cidade/UF, CEP) obtidos via empresas vinculadas ou registros públicos.
     - **Telefones & E-mails Vinculados**: Contatos extraídos de registros públicos e cadastros empresariais.
     - **Processos Judiciais & Atos Oficiais**: Contagem e destaque dos processos CNJ encontrados.
   - Seções detalhadas redesenhadas e separadas com clareza:
     1. `FICHA CONSOLIDADA DO ALVO`
     2. `EMPRESAS & PARTICIPAÇÕES SOCIETÁRIAS (QSA / RECEITA FEDERAL)` (com endereço completo, telefone, e-mail, capital social e sócios)
     3. `PROCESSOS JUDICIAIS & JURISPRUDÊNCIA (CNJ / TRIBUNAIS)`
     4. `DIÁRIOS OFICIAIS, EDITAIS & REGISTROS PÚBLICOS`
     5. `ENDEREÇOS, TELECOMUNICAÇÕES & LOCALIZAÇÃO`
     6. `PERFIS DIGITAIS, REDES SOCIAIS & EXPOSIÇÃO EM VAZAMENTOS`

### Não-Objetivos (Non-Goals)
- Integração com bureaus de crédito privados/pagos (Serasa, Boa Vista, SPC) ou bases ilegais.
- Quebra de CAPTCHAs ou contorno de controles de acesso autenticados.

### Anti-Objetivos (Anti-Goals)
- **Zero Enrolação / Zero Filler Genérico**: O CLI não deve exibir cards dizendo `"Compliance Check CEIS/CNEP: Sem restrições"` ou `"DataJud Index: <alvo>"` quando nenhuma informação real foi encontrada. Se uma fonte não encontrou registros para o alvo, ela não polui o dossiê.
- **Zero Truncamento de Dados Críticos**: Nomes de empresas, endereços, números de processo CNJ e URLs clicáveis nunca devem ser cortados com `...` no terminal.

---

## 3. Restrições (Constraints)

- **100% Gratuito (Zero-Key Ready)**: Deve funcionar imediatamente sem exigir nenhuma chave paga no `.env`, aproveitando chaves opcionais (`GODSEYE_PORTAL_TRANSPARENCIA_API_KEY`, `GODSEYE_DATAJUD_API_KEY`) apenas como enriquecimento adicional se o usuário decidir configurá-las.
- **Compatibilidade com a Suíte de Testes Existente**: Os testes automatizados em `tests/` que validam a resiliência e o pipeline básico devem continuar passando (100% green).
- **Respeito à LGPD e Auditoria**: Toda observação gerada continua armazenando `RawEvidence` com hash `SHA-256`, URL de origem e timestamp UTC.

---

## 4. Abordagens Consideradas e Decisão

1. **Abordagem 1 (Escolhida): Descoberta Multi-Fonte + Pivô Automático em Cascata + Ficha Consolidada no CLI**
   - Combina buscadores públicos gratuitos + Diários Oficiais + APIs públicas de CNPJ/CEP/DDD/DataJud em dois ou três saltos automáticos (`Nome / CPF / Telefone ➔ CNPJ / Nome / Processo / CEP ➔ Dados Cadastrais Completos da Receita Federal`).
   - *Motivo da escolha:* É a única arquitetura 100% gratuita capaz de descobrir vínculos societários, endereços comerciais completos e processos judiciais a partir de um Nome, CPF ou Telefone.
2. **Abordagem 2 (Descartada): Apenas APIs Governamentais Diretas sem Buscadores Web**
   - *Trade-off:* Como `BrasilAPI` e `CNPJ.ws` exigem o número do CNPJ como chave de entrada, não seria possível descobrir empresas no nome de uma pessoa apenas pelo Nome ou CPF fora de diários municipais.
3. **Abordagem 3 (Descartada): Scrapers Acoplados a Portais Específicos**
   - *Trade-off:* Bloqueios constantes por WAF/Cloudflare tornam a solução instável sem proxies pagos.

---

## 5. Especificação Técnica Detalhada (The How)

### 5.1 Motor de Busca e Extração Pública (`godseye/collectors/brazil_sources.py`)

Criaremos um utilitário assíncrono compartilhado `search_public_web_records(http_client, source_id, queries)` e extratores estruturados em `brazil_sources.py`:
- **Decodificação de Resultados Web**:
  - Consulta endpoints HTML leves de busca (`https://html.duckduckgo.com/html/` e fallback `https://lite.duckduckgo.com/lite/`) decodificando parâmetros `uddg=` (`urllib.parse.unquote`) para obter a URL pública real (e não o link intermediário do DuckDuckGo).
- **Extratores Regex de Alta Precisão (`extract_brazil_entities_from_text`)**:
  - **CNPJs**: `\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b` (validados pelo algoritmo Módulo-11 de CNPJ para descartar falsos positivos numéricos).
  - **Processos Judiciais CNJ**: `\b\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}\b` + inferência automática do ramo/tribunal pelo código CNJ (`J.TR`, ex.: `8.26` = TJSP, `8.19` = TJRJ, `8.13` = TJMG, `4.01`..`4.06` = TRF1..TRF6, `5.01`..`5.24` = TRT).
  - **CEPs**: `\b\d{5}-\d{3}\b`.
  - **Telefones Brasileiros**: `(?:\+?55\s*)?\(?\d{2}\)?\s*9?\d{4}[-\s]?\d{4}`.
  - **Nomes Civis Próximos ao Alvo**: heurística aprimorada `extract_names_near_cpf` e extração de razão social / sócios em snippets de quadro societário.

### 5.2 Evolução dos Coletores Brasileiros e de Pessoa/Telefone

1. **`BrasilApiCnpjCollector` (`brazil_sources.py`)**:
   - Consulta `https://brasilapi.com.br/api/cnpj/v1/{cnpj}`. Se indisponível ou rate-limited, faz fallback real para `https://publica.cnpj.ws/cnpj/{cnpj}` e `https://receitaws.com.br/v1/cnpj/{cnpj}`.
   - Extrai e salva no `raw_payload`:
     - `cnpj`, `razao_social`, `nome_fantasia`, `situacao_cadastral`, `data_inicio_atividade`, `cnae_principal`, `capital_social`
     - `logradouro`, `numero`, `complemento`, `bairro`, `municipio`, `uf`, `cep`, `endereco_completo` (formatado: `"Rua X, 123, Compl, Bairro - Cidade/UF, CEP 00000-000"`)
     - `telefones` (lista de telefones formatados a partir de `ddd_telefone_1`, `ddd_telefone_2`) e `email`
     - `qsa` completo (lista de sócios com `nome_socio`, `qualificacao_socio`, `faixa_etaria`, `documento_masked`)
   - Emite observações para a Organização, Localização (endereço completo), Sócios (`EntityType.PERSON`), Telefones (`EntityType.PHONE`) e E-mail (`EntityType.EMAIL`).

2. **`BrasilCpfOsintCollector` (`brazil_sources.py`)**:
   - Executa em paralelo:
     - Consulta ao Portal da Transparência (se chave configurada).
     - Consulta ao `Querido Diário` pelo CPF formatado e apenas dígitos.
     - Buscas públicas direcionadas:
       - Query geral: `"{cpf_fmt}" OR "{digits}"`
       - Query societária/jurídica: `"{cpf_fmt}" ("CNPJ" OR "sócio" OR "processo" OR "edital")`
   - Extrai: `discovered_names`, `discovered_cnpjs` (validados por Mod-11), `discovered_processes` (padrão CNJ + tribunal), `discovered_addresses`, `public_mentions`.
   - Emite observações `EntityType.PERSON` (para cada nome descoberto), `EntityType.ORGANIZATION` (com `discovered_cnpj` para pivô automático), `EntityType.LEGAL_CASE` (para cada processo CNJ encontrado) e `EntityType.DOCUMENT`.

3. **`PublicPersonAndLeakCollector` (`expansion_sources.py`)**:
   - Quando `target.type == TargetType.PERSON` (busca por Nome Completo):
     - Além de GitHub e Wikipedia, realiza busca pública brasileira de vínculos:
       - Empresas/QSA no nome: `"{nome}" ("sócio" OR "administrador" OR "CNPJ" OR "quadro societário")`
       - Processos judiciais no nome: `"{nome}" ("processo" OR "tribunal" OR "TJ" OR "TRF" OR "TRT" OR "diário da justiça")`
     - Filtra resultados garantindo que o nome pesquisado (tokens significativos sem acento) apareça no título ou snippet.
     - Extrai `discovered_cnpjs` (validados por Mod-11), `discovered_processes` (números CNJ e menções judiciais), `discovered_phones`, `discovered_addresses` e emite observações `EntityType.ORGANIZATION`, `EntityType.LEGAL_CASE` e `EntityType.DOCUMENT`.

4. **`DataJudCnjCollector` (`brazil_sources.py`)**:
   - Passa a aceitar `{TargetType.PROCESSO, TargetType.CNPJ, TargetType.PERSON}`.
   - Decodifica metadados reais de qualquer número CNJ (`NNNNNNN-NN.NNNN.N.NN.NNNN`): ano do ajuizamento, segmento do Judiciário (Justiça Estadual, Federal, Trabalhista, Eleitoral, Superior), tribunal (`TJSP`, `TJRJ`, `TRF1..6`, `TRT1..24`, etc.) e unidade de origem.
   - Se `GODSEYE_DATAJUD_API_KEY` (ou a chave pública da API Pública do CNJ) estiver disponível e o alvo for um processo ou parte, consulta o endpoint do tribunal correspondente no DataJud (`https://api-publica.datajud.cnj.jus.br/api_publica_{sigla}/_search`) e complementa com busca indexada em diários de justiça / tribunais.
   - Remove o stub genérico `"DataJud/CNJ Index: {val}"` para alvos que não retornarem processos reais (mantendo-o apenas quando `target.type == TargetType.PROCESSO` com decodificação completa do número CNJ).

5. **`PhoneOsintCollector` (`expansion_sources.py`)**:
   - Além da validação E.164 e consulta de DDD na BrasilAPI, faz busca pública do número nos formatos nacional (`(DD) 9XXXX-XXXX`, `DD 9XXXX-XXXX`, `DD9XXXXXXXX`) para localizar:
     - Empresas (`CNPJs`) que registram esse telefone como contato comercial.
     - Nomes de titulares/responsáveis ou editais públicos onde o telefone aparece.
   - Emite observações com `discovered_cnpj` e `discovered_person_name` para que o orquestrador pivote automaticamente.

6. **`PortalTransparenciaSanctionsCollector` (`brazil_sources.py`)**:
   - Deixa de emitir o card genérico `"Compliance Check CEIS/CNEP: ... (Sem restrições ativas detectadas)"` quando não há sanção real, evitando poluir o relatório do CLI (emite apenas quando uma sanção real é encontrada ou quando `offline_fallback` é exigido especificamente em testes de CNPJ sem rede).

### 5.3 Pivô Automático em Cascata (`godseye/services/orchestrator.py`)

Em `_derive_cascading_targets`:
- **Pessoa / CPF / Telefone ➔ CNPJ**: Qualquer observação que contenha `raw_payload.get("discovered_cnpj")` (ou `entity_type == EntityType.ORGANIZATION` com CNPJ válido de 14 dígitos ainda não visitado) gera um `Target(type=TargetType.CNPJ)` no próximo salto (até 3 CNPJs por alvo), disparando `BrasilApiCnpjCollector` para buscar razão social, endereço completo, telefones e sócios.
- **CPF / Telefone ➔ Nome da Pessoa**: Qualquer observação com `raw_payload.get("discovered_person_name")` gera um `Target(type=TargetType.PERSON)` para investigar empresas, processos e perfis daquele nome.
- **Processo CNJ descoberto ➔ `TargetType.PROCESSO`**: Enriquecido com metadados do tribunal.

### 5.4 Novo Layout de Dossiê no CLI (`godseye/cli/main.py`)

O método `_render_scan_report` será reestruturado para apresentar:
1. **Cabeçalho Compacto da Operação** (Alvo, Tipo, Profundidade, Fontes Ativas, Tempo).
2. **Painel Principal: `𓂀 FICHA CONSOLIDADA DO ALVO (RESUMO EXECUTIVO)`**:
   - **Nome / Titular Identificado**: Nome(s) civil(is) ou Razão Social principal.
   - **Documento(s)**: CPF (com status matemático e região fiscal em 1 linha limpa) e/ou CNPJ(s) vinculados.
   - **Endereços Localizados**: Lista consolidada de endereços completos (Rua, Número, Bairro, Cidade/UF, CEP) vindos de CNPJs vinculados, CEPs ou documentos públicos.
   - **Telefones & E-mails Encontrados**: Lista direta de telefones e e-mails associados ao alvo.
   - **Resumo de Vínculos**: `X Empresa(s) no Nome (QSA)  •  Y Processo(s) Judicial(is)  •  Z Perfil(is) Digital(is)`.
3. **Seções Detalhadas (Exibidas apenas quando houver dados reais)**:
   - **`𓂀 EMPRESAS & QUADRO SOCIETÁRIO (RECEITA FEDERAL / QSA)`**: Razão Social, Nome Fantasia, CNPJ, Situação, Data de Abertura, Capital Social, CNAE, **Endereço Completo**, **Telefone/E-mail da Empresa** e lista de Sócios.
   - **`𓂀 PROCESSOS JUDICIAIS & TRIBUNAIS (CNJ / DIÁRIOS DA JUSTIÇA)`**: Número do processo CNJ, Tribunal/Ramo da Justiça, Classe/Assunto, trecho/partes e link clicável.
   - **`𓂀 DIÁRIOS OFICIAIS, EDITAIS & MENÇÕES PÚBLICAS`**: Publicações municipais/estaduais/federais com data, órgão, resumo e link completo.
   - **`𓂀 TELECOMUNICAÇÕES & LOCALIZAÇÃO (GEOINT)`**: Dados do telefone/DDD, vínculo encontrado e endereços/CEPs.
   - **`𓂀 PERFIS DIGITAIS, REDES & EXPOSIÇÃO EM VAZAMENTOS`**: Contas encontradas (GitHub, redes sociais, Gravatar, Keybase) e vazamentos (XposedOrNot, Hudson Rock, HIBP).
   - **`𓂀 GRAFO DE VÍNCULOS DESCOBERTOS`**: Árvore visual conectando Alvo ➔ Empresas ➔ Endereços ➔ Sócios ➔ Processos.

---

## 6. O Que Fica a Critério do Implementador (Left to the Builder)

- Detalhes exatos de *timeouts* por requisição nos buscadores web secundários (desde que cada busca individual não ultrapasse `4s-6s` para manter o scan rápido).
- Mapeamento completo dos códigos de tribunais CNJ (`8.01` a `8.27`, `4.01` a `4.06`, `5.01` a `5.24`) em um dicionário auxiliar em `brazil_sources.py`.
- Ajustes de cores e espaçamento nas tabelas/painéis do `Rich` em `godseye/cli/main.py`.
