# Expansão do Agregador OSINT: Módulos, Fontes e APIs

Documento complementar à arquitetura do agregador OSINT e à lista de APIs brasileiras. Ele define os próximos módulos recomendados, as fontes/APIs que podem ser utilizadas e as regras de uso seguro.

> **Regra central:** o diferencial da plataforma não é apenas ter muitas APIs, mas permitir que o analista parta de um CPF, CNPJ, placa, e-mail, domínio, telefone ou endereço cripto e chegue a um dossiê auditável, com grafo, evidências, alertas e conclusões verificáveis.

---

## 1. Módulos recomendados

| Módulo | Objetivo | Prioridade |
|---|---|---|
| **Watchlists e alertas** | Monitorar entidades e gerar alertas quando houver nova informação | Alta |
| **Phone OSINT** | Validar, enriquecer e correlacionar números telefônicos | Alta |
| **Catálogo brasileiro dinâmico** | Descobrir e habilitar fontes públicas brasileiras automaticamente | Alta |
| **Cripto OSINT** | Investigar carteiras, transações, exchanges e risco de endereços | Média |
| **Dark web, pastes e fóruns** | Monitorar menções, exposição e indicadores de comprometimento | Média |
| **Colaboração investigativa** | Permitir trabalho em equipe, revisão e versionamento | Média |
| **Qualidade e governança de dados** | Pontuar confiabilidade, detectar conflitos e exigir revisão humana | Alta |
| **IA assistiva** | Resumo, tradução, extração e sugestão de hipóteses | Média |
| **Monitoramento de superfície de ataque** | Acompanhar domínios, subdomínios, certificados e serviços expostos | Média |
| **Mídia e imagem** | Busca reversa, OCR, metadados e verificação visual | Média |

---

## 2. Watchlists e alertas

Transforma a plataforma de um buscador pontual em um sistema de inteligência contínua.

### 2.1 Casos de uso

- Novo processo envolvendo CNPJ monitorado.
- Empresa entra em CEIS, CNEP, CEAF ou CEPIM.
- Domínio recebe novo subdomínio ou certificado.
- E-mail aparece em novo vazamento.
- Username altera avatar, bio, localização ou vínculos.
- Endereço cripto aparece em lista de sanções.
- Empresa é citada em diário oficial, contrato público ou notícia.
- Veículo monitorado recebe nova restrição, leilão ou sinistro, quando autorizado.

### 2.2 Modelo de dados

```text
Watchlist
  id, case_id, entity_id, type, value, alert_rules[],
  frequency, channels[], owner, active, created_at

Alert
  id, watchlist_id, triggered_at, source_id, evidence_id,
  severity, message, acknowledged_by, acknowledged_at

AlertRule
  id, watchlist_id, event_type, condition, threshold,
  severity, cooldown_minutes, enabled
```

### 2.3 Eventos que podem disparar alertas

```text
entity.created
entity.updated
entity.merged
relationship.created
breach.detected
sanction.detected
legal_case.created
legal_case.updated
domain.certificate_issued
domain.subdomain_discovered
crypto.address_flagged
news.mention_detected
official_gazette.mention_detected
```

### 2.4 APIs e fontes

| Fonte | Uso no monitoramento |
|---|---|
| **DataJud/CNJ** | Novos processos e movimentações |
| **DOU/INLabs** | Publicações federais |
| **Querido Diário** | Diários municipais |
| **Portal da Transparência** | Contratos, sanções e convênios |
| **CEIS/CNEP/CEAF/CEPIM** | Sanções e inidoneidade |
| **HIBP** | Novos vazamentos envolvendo e-mail/domínio |
| **Intelligence X** | Menções em leaks, pastes e dark web |
| **crt.sh / CertStream** | Novos certificados e subdomínios |
| **Shodan / Censys** | Mudanças em serviços expostos |
| **Google News RSS / GDELT** | Menções em notícias |
| **TSE** | Candidaturas, doações e prestação de contas |
| **OpenSanctions** | Sanções, PEPs e listas de risco |

---

## 3. Phone OSINT

Adiciona o telefone como identificador de primeira classe, ao lado de e-mail, username, CPF, CNPJ e domínio.

### 3.1 Capacidades

- Validação e normalização E.164.
- Identificação de país, DDD, operadora original e portabilidade.
- Classificação: móvel, fixo, VoIP, temporário ou desconhecido.
- Verificação de WhatsApp/Telegram somente por métodos permitidos.
- Busca reversa apenas em serviços licenciados.
- Correlação com e-mails, usernames, perfis públicos e empresas.

### 3.2 Modelo de dados

```text
Phone
  id, e164, national_format, country, area_code,
  carrier_original, carrier_current, line_type,
  portability_status, risk_score, first_seen, last_seen

PhoneObservation
  id, phone_id, source_id, observed_at, confidence,
  raw_payload, source_url, adapter_version

PhoneRelationship
  id, phone_id, related_entity_id, relation,
  confidence, evidence_id
```

### 3.3 APIs e fontes

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Numverify** | Validação, operadora, tipo de linha e geolocalização | Freemium |
| **Twilio Lookup** | Validação, carrier, tipo de linha e SIM swap | Freemium |
| **PhoneInfoga** | Enumeração e reconhecimento de números | Gratuito/open source |
| **Truecaller** | Identificação e spam, conforme ToS | Comercial |
| **Infobel** | Diretórios telefônicos e dados de contato | Comercial |
| **FoneFinder** | Operadora, região e tipo de número | Gratuito |
| **WhatsApp Business API** | Verificação e interação autorizada | Oficial |
| **Telegram Bot API** | Automação em canais/bots autorizados | Gratuito |
| **Anatel** | Outorgas, radiação e dados regulatórios | Gratuito |
| **Consulta Operadora** | Portabilidade e operadora atual | Oficial/comercial |

### 3.4 Regras

- Não inferir titularidade apenas a partir do número.
- Não armazenar conversas, contatos ou conteúdo privado.
- Exigir base legal para busca reversa de titular.
- Registrar finalidade, operador e evidência de cada consulta.
- Tratar identificação de pessoa física como dado pessoal sensível.

---

## 4. Catálogo brasileiro dinâmico

Use o **OSINT Brazuca** como catálogo dinâmico de fontes brasileiras, não como fonte primária de dados.

### 4.1 O que ele oferece

- Mais de 510 fontes em 39 categorias.
- Índice por entrada: CPF, CNPJ, placa, domínio, telefone.
- Taxonomia com tipos de entrada, retorno e origem.
- Foco em fontes públicas, legais e verificáveis.
- JSON estruturado para importação em um `Collector Registry`.

### 4.2 Repositórios e referências

| Recurso | URL | Uso |
|---|---|---|
| **OSINT Brazuca** | https://github.com/osintbrazuca/osint-brazuca | Catálogo de fontes brasileiras |
| **Página do projeto** | https://hysenlabs.com/projects/osintbrazuca-osint-brazuca | Visão geral e documentação |
| **DeepWiki — Public Databases** | https://deepwiki.com/osintbrazuca/osint-brazuca/8-public-databases-and-open-data-resources | Bases públicas brasileiras |
| **OSINT BRASIL** | https://osintbrasil.app.br/ | Agregador de fontes públicas e verificáveis |

### 4.3 Integração sugerida

```text
CatalogImporter
  ├── Baixa JSON do OSINT Brazuca
  ├── Valida schema
  ├── Mapeia categoria → Collector Category
  ├── Mapeia input_type → TargetType
  ├── Cria/atualiza Source
  └── Marca fonte como "candidate" até revisão humana
```

### 4.4 Campos recomendados no catálogo interno

```text
Source
  id, name, provider, country, category, input_types[],
  output_types[], access_type, requires_auth, tos_url,
  documentation_url, trust_level, rate_limit, cost,
  status, last_reviewed_at
```

---

## 5. Cripto OSINT

Permite investigar carteiras, transações, exchanges, golpes e vínculos entre endereços.

### 5.1 Capacidades

- Identificação de blockchain por formato de endereço.
- Consulta de saldo, transações e tokens.
- Rastreamento de fluxo entre carteiras.
- Identificação de exchanges, mixers e contratos.
- Verificação em listas de sanções e golpes.
- Correlação com fóruns, redes sociais e pastes.
- Clusterização de endereços, quando a fonte permitir.

### 5.2 Modelo de dados

```text
CryptoWallet
  id, address, blockchain, label, risk_score,
  first_seen, last_seen

CryptoTransaction
  id, blockchain, tx_hash, from_address, to_address,
  value, token, timestamp, block, source_id

CryptoCluster
  id, label, addresses[], confidence, source_id,
  attribution, evidence_id
```

### 5.3 APIs e fontes

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Etherscan** | Transações, tokens, contratos e endereços Ethereum | Freemium |
| **BscScan** | Dados da BNB Chain | Freemium |
| **PolygonScan** | Dados da Polygon | Freemium |
| **Solscan** | Transações e carteiras Solana | Freemium |
| **Tronscan** | Transações e carteiras Tron | Gratuito |
| **Blockchain.com Explorer** | Bitcoin, Ethereum e outras redes | Gratuito |
| **Blockchair** | Busca multi-blockchain | Freemium |
| **BlockCypher** | Dados de Bitcoin e outras redes | Freemium |
| **BitQuery** | Consultas avançadas multi-chain | Freemium |
| **Arkham Intelligence** | Atribuição, entidades e fluxo de carteiras | Freemium |
| **Breadcrumbs** | Análise de fluxo e visualização | Freemium |
| **Whale Alert** | Transferências relevantes em tempo real | Freemium |
| **Chainalysis** | Investigação, risco e conformidade | Comercial |
| **TRM Labs** | Risco, sanções e investigação cripto | Comercial |
| **Crystal Blockchain** | Análise forense de blockchain | Comercial |
| **CryptoScamDB** | Endereços e golpes reportados | Gratuito |
| **OpenSanctions** | Sanções e listas de risco | Gratuito |

### 5.4 Fluxo recomendado

```text
Endereço cripto
   ↓
Identifica blockchain
   ↓
Consulta explorador
   ↓
Extrai transações e contrapartes
   ↓
Consulta sanções e listas de risco
   ↓
Busca endereço em pastes, fóruns e redes sociais
   ↓
Gera grafo de fluxo e cluster
   ↓
Produz alerta se houver risco
```

---

## 6. Dark web, pastes e fóruns

O objetivo é monitorar **menções, exposição e indicadores**, não armazenar dumps brutos.

### 6.1 O que monitorar

- Pastes públicos.
- Fóruns abertos.
- Marketplaces públicos, quando legal.
- Sites de vazamento de ransomware.
- Canais públicos de Telegram.
- Repositórios públicos com segredos expostos.
- Menções a domínios, e-mails corporativos, marcas e funcionários.

### 6.2 APIs e fontes

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Intelligence X** | Leaks, pastes, dark web, documentos e histórico | Freemium |
| **DeHashed** | Registros de vazamento e exposição | Freemium |
| **HIBP** | Exposição de e-mail e domínio | Freemium |
| **Hudson Rock** | Exposição corporativa em infostealers | Freemium |
| **URLhaus** | URLs maliciosas | Gratuito |
| **ThreatFox** | IOCs de malware | Gratuito |
| **MalwareBazaar** | Amostras e metadados de malware | Gratuito |
| **AlienVault OTX** | IOCs, pulses e threat intelligence | Gratuito |
| **GitHub Search API** | Segredos e código exposto | Freemium |
| **Gitleaks** | Detecção de credenciais em Git | Gratuito |
| **TruffleHog** | Varredura de segredos | Gratuito |
| **Telegram Bot API** | Monitoramento de canais autorizados | Gratuito |

### 6.3 Regras obrigatórias

- Não baixar, armazenar ou redistribuir dumps brutos.
- Não expor senhas em texto claro.
- Armazenar apenas metadados: fonte, URL, hash, timestamp e trecho mínimo necessário.
- Usar serviços licenciados para busca em leaks.
- Registrar finalidade, operador e trilha de auditoria.

---

## 7. Colaboração investigativa

Adiciona camada humana ao sistema, evitando que ele vire apenas um aglomerado de resultados.

### 7.1 Funcionalidades

- Comentários por caso, entidade, evidência e relação.
- Tarefas e atribuição de responsável.
- Status de verificação: `não verificado`, `corroborado`, `contestado`, `falso positivo`.
- Versionamento do dossiê.
- Menções a colegas em notas.
- Exportação com trilha de auditoria.
- Aprovação humana para conclusões sensíveis.

### 7.2 Modelo de dados

```text
CaseComment
  id, case_id, entity_id, evidence_id, author_id,
  body, mentions[], created_at, edited_at

Task
  id, case_id, title, description, assignee_id,
  status, due_date, created_by, created_at

Verification
  id, entity_id, relationship_id, status, reviewer_id,
  reason, evidence_id, reviewed_at

CaseVersion
  id, case_id, version, snapshot_url, created_by,
  created_at, change_summary
```

---

## 8. Qualidade e governança de dados

### 8.1 Score de confiabilidade

Calcule um score por observação e relação:

```text
confidence =
  source_trust
  + source_recency
  + corroboration_count
  + official_source_bonus
  - conflict_penalty
  - stale_data_penalty
```

### 8.2 Classificação de fontes

| Nível | Exemplos |
|---|---|
| **Oficial** | Receita Federal, CNJ, TSE, IBGE, tribunais, gov.br |
| **Alta** | HIBP, Shodan, Censys, VirusTotal, urlscan |
| **Média** | Agregadores comerciais e diretórios |
| **Baixa** | Fóruns, redes sociais e fontes não verificadas |

### 8.3 Regras de qualidade

- Priorize fonte primária sobre secundária.
- Marque dados antigos como possivelmente desatualizados.
- Detecte conflitos entre fontes.
- Permitir contestar relações incorretas.
- Exigir revisão humana para conclusões sensíveis.
- Guardar explicação de cada inferência.

### 8.4 Modelo de dados

```text
DataQualityScore
  id, observation_id, relationship_id, source_trust,
  recency, corroboration_count, conflict_penalty,
  stale_penalty, final_score, calculated_at

DataConflict
  id, entity_id, observation_a_id, observation_b_id,
  conflict_type, status, resolved_by, resolved_at
```

---

## 9. IA assistiva

Use IA como camada de apoio, nunca como fonte de verdade.

### 9.1 Casos de uso

- Resumir dossiê.
- Traduzir documentos.
- Extrair entidades de PDFs e diários oficiais.
- Sugerir possíveis relações.
- Agrupar notícias semelhantes.
- Gerar rascunho de relatório.
- Explicar por que duas entidades foram conectadas.

### 9.2 Regras

- Toda saída de IA deve ser marcada como `model_generated`.
- IA não pode criar relação sem evidência.
- IA não pode alterar score de confiança sem revisão.
- Guarde prompt, modelo, versão, custo e resultado.
- Permita rejeitar ou corrigir sugestões da IA.

### 9.3 Modelo de dados

```text
AIInference
  id, case_id, input_evidence_ids[], model, model_version,
  prompt_hash, output, confidence_kind, human_review_status,
  created_at, reviewed_by, reviewed_at
```

---

## 10. Monitoramento de superfície de ataque

### 10.1 Casos de uso

- Novos subdomínios.
- Novos certificados TLS.
- Novas portas e serviços expostos.
- Mudanças em DNS.
- Tecnologia exposta com CVE conhecida.
- Página de login exposta.
- Painéis administrativos indexados.

### 10.2 APIs e fontes

| Fonte/API | Uso |
|---|---|
| **Shodan** | Serviços, portas, banners e CVEs |
| **Shodan InternetDB** | Consulta rápida por IP |
| **Censys** | Hosts, certificados e superfície de ataque |
| **crt.sh** | Certificados e subdomínios |
| **CertStream** | Novos certificados em tempo real |
| **urlscan.io** | Análise e histórico de URLs |
| **Wayback Machine** | Histórico de páginas |
| **VirusTotal** | Reputação e detecção |
| **AbuseIPDB** | Reputação de IP |
| **GreyNoise** | Ruído e scanners |

---

## 11. Mídia, imagem e verificação

### 11.1 Casos de uso

- Busca reversa de avatar.
- Verificação de local por imagem.
- Extração de metadados EXIF.
- OCR em documentos e prints.
- Detecção de manipulação visual.
- Identificação de objetos, placas e landmarks.

### 11.2 APIs e fontes

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **TinEye** | Busca reversa de imagens | Freemium |
| **Google Vision API** | OCR, objetos, texto e landmarks | Freemium |
| **Clarifai** | Reconhecimento visual | Freemium |
| **Sightengine** | Análise e moderação de mídia | Freemium |
| **ExifTool** | Metadados EXIF | Gratuito |
| **Mapillary** | Imagens street-level | Freemium |
| **Google Maps / Street View** | Verificação de local | Freemium |
| **OpenStreetMap** | Mapa e POIs | Gratuito |

---

## 12. APIs brasileiras adicionais

| Área | Fonte/API | O que fornece | Acesso |
|---|---|---|---|
| **Empresas** | Receita Federal — Dados Abertos CNPJ | Base nacional de CNPJ | Gratuito |
| **Empresas** | API CNPJ Conecta/SERPRO | Consulta Básica, QSA e Empresa | Oficial |
| **Empresas** | BrasilAPI | CNPJ, CEP, bancos e dados públicos | Gratuito |
| **Processos** | DataJud/CNJ | Metadados e movimentações processuais | Oficial |
| **Processos** | PJe | Processos eletrônicos | Oficial |
| **Processos** | e-SAJ | Processos e publicações | Oficial |
| **Diários** | DOU/INLabs | Diário Oficial da União | Gratuito |
| **Diários** | Querido Diário | Diários municipais | Gratuito |
| **Sanções** | CEIS/CNEP/CEAF/CEPIM | Sanções e inidoneidade | Gratuito |
| **Transparência** | Portal da Transparência | Contratos, despesas e sanções | Gratuito |
| **Licitações** | PNCP | Licitações e contratos públicos | Gratuito |
| **Eleições** | TSE DivulgaCandContas | Candidatos, bens e contas | Gratuito |
| **Veículos** | WSDenatran/SERPRO | Veículos, condutores e infrações | Oficial/contratado |
| **Veículos** | Consultar Placa Veicular | Validação por placa Mercosul + QR Code | Gratuito |
| **Geografia** | IBGE | Municípios, estados, códigos e estatísticas | Gratuito |
| **Endereço** | ViaCEP / BrasilAPI | CEP e endereço | Gratuito |
| **Marcas** | INPI | Marcas, patentes e desenhos industriais | Gratuito |
| **Financeiro** | Banco Central / CVM | Instituições, fundos e dados regulatórios | Gratuito |
| **Ambiental** | IBAMA / CAR / SIGEF | Embargos, imóveis rurais e cadastros | Gratuito |

---

## 13. APIs internacionais complementares

| Área | Fonte/API | Uso |
|---|---|---|
| **Vazamentos** | HIBP, Intelligence X, DeHashed, LeakCheck | Exposição de e-mail/domínio |
| **Infraestrutura** | Shodan, Censys, ZoomEye, Fofa, Netlas | Ativos expostos |
| **Threat Intel** | VirusTotal, OTX, MISP, ThreatFox, URLhaus | IOCs e reputação |
| **Código** | GitHub, GitLab, Sourcegraph, Gitleaks, TruffleHog | Código e segredos |
| **SOCMINT** | Bluesky, Mastodon, Reddit, Telegram, YouTube | Perfis e conteúdo público |
| **GEOINT** | Nominatim, Overpass, Mapillary, Copernicus, NASA | Localização e satélite |
| **Imagens** | TinEye, Google Vision, Clarifai, ExifTool | Busca reversa e metadados |
| **Cripto** | Etherscan, Blockchair, Arkham, Breadcrumbs, BitQuery | Carteiras e transações |
| **Compliance** | OpenSanctions, OFAC, ONU, UE | Sanções e PEPs |
| **Empresas** | OpenCorporates, Companies House, SEC EDGAR | Registros corporativos |

---

## 14. Roadmap de implementação

### Fase 1 — Imediato

1. Watchlists e alertas.
2. Catálogo OSINT Brazuca.
3. Phone OSINT básico.
4. Qualidade e score de confiança.
5. Auditoria reforçada.

### Fase 2 — Expansão

1. Cripto OSINT.
2. Dark web e pastes via serviços licenciados.
3. Colaboração investigativa.
4. Monitoramento de superfície de ataque.
5. Relatórios versionados.

### Fase 3 — Produto avançado

1. IA assistiva com revisão humana.
2. Análise preditiva de risco.
3. Integrações externas.
4. API pública controlada.
5. Marketplace de conectores.

---

## 15. O que não implementar agora

- Scraping agressivo de gov.br, tribunais ou Denatran.
- Busca irrestrita por CPF ou titular de placa.
- Armazenamento de senhas em texto claro ou dumps completos.
- IA generativa como fonte de verdade.
- Integração simultânea com todas as APIs disponíveis.
- Coleta sem finalidade registrada, base legal e auditoria.

---

## 16. Prioridade final

A ordem mais eficiente para evoluir a plataforma é:

1. **Watchlists e alertas** — maior valor imediato.
2. **Phone OSINT** — complementa e-mail, username e CNPJ.
3. **Catálogo OSINT Brazuca** — acelera cobertura brasileira.
4. **Cripto OSINT** — relevante para fraudes e compliance.
5. **Dark web/pastes** — apenas via serviços licenciados.
6. **Colaboração e qualidade de dados** — essencial para uso profissional.
