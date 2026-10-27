# Documentação: Backend de um Agregador OSINT

## 1. Visão geral

Este documento descreve a arquitetura de um backend para uma plataforma OSINT (*Open Source Intelligence*) que agrega informações públicas de múltiplas fontes — contas, usuários, e-mails, domínios, IPs, empresas, documentos públicos e exposição em vazamentos — mantendo proveniência, auditoria, controle de acesso e limites legais.

A premissa central é: **a ferramenta não deve ser uma fonte única, mas um hub de agregação e correlação**. Cada fonte permanece independente, com sua própria API, autenticação, limites, confiabilidade e evidência original.

> **Importante:** a plataforma deve ser usada apenas para finalidades legítimas e autorizadas. Não armazene, redistribua ou indexe dumps brutos de credenciais, senhas em texto claro ou dados pessoais sem base legal, minimização e controles de acesso.

---

## 2. Princípios de design

- **Fontes plugáveis:** cada provedor é um adaptador isolado, sem acoplamento ao núcleo.
- **Orientado a casos:** toda coleta pertence a um caso investigativo com escopo, responsável e finalidade.
- **Evento-driven:** coletores produzem e consomem eventos tipados, permitindo descoberta em cascata.
- **Evidência primeiro:** o sistema guarda o achado original, fonte, URL, timestamp, hash e payload antes de qualquer inferência.
- **Proveniência obrigatória:** todo dado possui origem, data de coleta, versão do adaptador e nível de confiança.
- **Correlação controlada:** relações entre entidades são inferências, não fatos; devem ter confiança e evidência.
- **Segurança por padrão:** RBAC, auditoria, segredos isolados, rate limiting, retenção e minimização de dados.
- **Escalabilidade gradual:** comece com PostgreSQL, Redis e workers; introduza grafo dedicado e busca textual apenas quando necessário.

---

## 3. Arquitetura de alto nível

```text
Frontend / API clients
        │
        ▼
API Gateway + Auth + Rate limit
        │
        ▼
Case Service ──► PostgreSQL (casos, usuários, auditoria)
        │
        ▼
Investigation Orchestrator ──► Redis / RabbitMQ
        │                         │
        ▼                         ▼
Collector Workers ─────────► Source Adapters
        │                         │
        ▼                         ▼
Normalization Service ──► Entity Resolution
        │
        ├──► PostgreSQL: entidades, evidências, relações
        ├──► Neo4j / ArangoDB: grafo investigativo
        ├──► OpenSearch: busca textual e timeline
        └──► Object Storage: snapshots, PDFs, imagens, exports
```

### Fluxo resumido

1. O analista cria um **caso** e adiciona um **alvo** — por exemplo, um e-mail.
2. O **Orchestrator** identifica os coletores compatíveis e enfileira jobs.
3. Os **Collector Workers** consultam APIs externas por meio de adapters.
4. As respostas brutas viram **evidências**.
5. O **Normalizer** transforma evidências em observações padronizadas.
6. O **Entity Resolution** deduplica e conecta entidades.
7. O **Correlation Engine** gera relações, alertas e novas consultas.
8. O analista visualiza grafo, timeline e dossiê final.

---

## 4. Serviços principais

| Serviço | Responsabilidade |
|---|---|
| **API Gateway** | Autenticação, autorização, rate limiting, versionamento `/api/v1`, idempotência e logs de acesso. |
| **Case Service** | Criação de casos, escopo, permissões, status, notas do analista e trilha de auditoria. |
| **Investigation Orchestrator** | Recebe alvos, decide coletores, controla profundidade, prioridade, dependências e limites. |
| **Collector Registry** | Catálogo de fontes: entradas aceitas, custo, autenticação, rate limit, confiabilidade, categoria e status. |
| **Collector Workers** | Executam adapters isolados — HIBP, Shodan, WHOIS, crt.sh, urlscan, redes sociais etc. |
| **Normalization Service** | Converte respostas heterogêneas em eventos e entidades padronizadas. |
| **Entity Resolution** | Deduplica e liga registros, como e-mail, username, perfil e domínio. |
| **Evidence Store** | Guarda achado original, URL, timestamp, hash, payload bruto e classificação de confiança. |
| **Graph Service** | Mantém pessoas, contas, e-mails, domínios, IPs, organizações e relações. |
| **Correlation Engine** | Aplica regras, como “e-mail em dois breaches” ou “username presente em cinco redes”. |
| **Reporting Service** | Gera dossiê, timeline, grafo, exportações JSON/CSV/PDF e bundle auditável. |

---

## 5. Fontes recomendadas

### 5.1 Diretórios e curadoria

- **Bellingcat Online Investigation Toolkit**
- **OSINT Framework**
- **IntelTechniques Tools**

Use-os como catálogo dinâmico para descobrir fontes por país, categoria e tipo de investigação.

### 5.2 Vazamentos e exposição

- **Have I Been Pwned (HIBP)** — primeira consulta para exposição de e-mail e domínio.
- **Intelligence X** — leaks, pastes, dark web e histórico.
- **DeHashed** — busca comercial mais ampla de registros de breach.
- **LeakCheck**
- **BreachDirectory**
- **Snusbase**
- **Hudson Rock**

**Regra:** utilize apenas APIs e serviços licenciados. Não ingira dumps brutos nem permita busca por senhas em texto claro.

### 5.3 Infraestrutura

- **Shodan**
- **Censys**
- **WHOIS/RDAP**
- **crt.sh**
- **DNSDumpster**
- **urlscan.io**
- **VirusTotal**

### 5.4 Pessoas, contas e usernames

- **Sherlock**
- **Maigret**
- **WhatsMyName**
- **Social Searcher**
- APIs públicas de redes sociais, quando permitido pelos termos de uso

Resultados de username devem ser tratados como **pistas**, não como identificação definitiva.

### 5.5 Registros públicos

- Data.gov
- PACER
- MuckRock
- Diários oficiais
- Tribunais
- Registros empresariais
- Cartórios e cadastros imobiliários, quando legalmente acessíveis

Para o Brasil, priorize:

- Receita Federal
- Juntas Comerciais
- Diários Oficiais
- Tribunais
- IBGE
- INPI
- ANVISA
- TSE
- Portais de transparência

### 5.6 GEOINT e imagens

- Google Earth
- Sentinel Hub / Copernicus
- Mapillary
- OpenStreetMap
- Yandex Images
- TinEye

### 5.7 Automação e correlação

- **SpiderFoot**
- **Maltego**
- **Recon-ng**
- **theHarvester**
- **Amass**

O SpiderFoot é uma referência útil porque utiliza módulos produtores/consumidores de eventos e mecanismos de correlação entre entidades.

---

## 6. Modelo de dados

Use PostgreSQL como fonte da verdade operacional. Use um banco de grafo apenas quando consultas de múltiplos saltos e visualização exigirem performance dedicada.

```text
Case
  id, title, owner, status, legal_basis, created_at, closed_at

Target
  id, case_id, type, value, normalized_value, risk,
  first_seen, last_seen

Source
  id, name, provider, category, trust_level, tos_url,
  auth_type, rate_limit, cost_per_call, enabled

CollectionJob
  id, case_id, target_id, source_id, status, priority,
  requested_at, started_at, finished_at, error, cost

RawEvidence
  id, job_id, source_id, url, retrieved_at, content_hash,
  raw_payload, retention_expires_at

NormalizedObservation
  id, evidence_id, entity_type, entity_value, observed_at,
  confidence, verification, tags

Entity
  id, type, canonical_value, aliases, first_seen, last_seen

EntityRelationship
  id, from_entity_id, to_entity_id, relation, confidence,
  evidence_id, first_seen, last_seen

AuditEvent
  id, actor_id, case_id, action, object_id, ip, user_agent,
  timestamp, metadata
```

### 6.1 Entidades-base

| Tipo | Exemplos |
|---|---|
| `Person` | Nome, apelido, foto pública |
| `Account` | Perfil em rede social, username |
| `Email` | Endereço de e-mail |
| `Phone` | Número telefônico |
| `Domain` | Domínio ou subdomínio |
| `IPAddress` | IPv4/IPv6 |
| `Organization` | Empresa, instituição, CNPJ |
| `Breach` | Incidente de vazamento |
| `Document` | PDF, decisão judicial, licitação, diário oficial |
| `Image` | Foto, avatar, imagem de perfil |
| `Location` | Endereço, coordenada, região |

### 6.2 Relações comuns

| Relação | Exemplo |
|---|---|
| `uses` | Pessoa usa e-mail |
| `owns` | Pessoa possui domínio |
| `appears_in` | E-mail aparece em breach |
| `resolves_to` | Domínio resolve para IP |
| `issued_for` | Certificado emitido para domínio |
| `associated_with` | Perfil associado a organização |
| `mentioned_in` | Entidade mencionada em documento |
| `located_at` | Organização localizada em endereço |

---

## 7. Contrato de coletor

Cada fonte deve implementar a mesma interface:

```python
from typing import AsyncIterator, Protocol, Set
from enum import Enum

class TargetType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    PERSON = "person"
    ORGANIZATION = "organization"
    IMAGE = "image"
    DOCUMENT = "document"

class TrustLevel(str, Enum):
    OFFICIAL = "official"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Target:
    type: TargetType
    value: str

class RawObservation:
    source_id: str
    entity_type: str
    entity_value: str
    observed_at: str
    confidence: float
    raw_payload: dict
    source_url: str | None

class Collector(Protocol):
    id: str
    name: str
    accepts: Set[TargetType]
    produces: Set[str]
    trust_level: TrustLevel
    requires_auth: bool
    rate_limit: int

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        ...
```

### 7.1 Metadados obrigatórios

Cada observação deve conter:

- `source_id`
- `source_name`
- `source_url`
- `retrieved_at`
- `adapter_version`
- `raw_payload`
- `content_hash`
- `confidence`
- `verification_status`
- `legal_basis`
- `retention_policy`

---

## 8. Exemplo de fluxo: investigação por e-mail

**Alvo:** `usuario@empresa.com`

1. O usuário cria um caso e adiciona o e-mail como alvo.
2. O Orchestrator enfileira:
   - HIBP
   - Intelligence X
   - DeHashed
   - WHOIS/RDAP do domínio
   - DNS e certificados
   - Shodan
   - urlscan.io
   - Enumeração de usernames
3. HIBP retorna, por exemplo, `breach:linkedin-2021`.
4. O Normalizer cria:
   - Entidade `Email`
   - Entidade `Breach`
   - Observação `email appeared_in breach`
5. O Correlation Engine cria a relação:

```text
email:usuario@empresa.com --appeared_in--> breach:linkedin-2021
```

6. Como o domínio é corporativo, o sistema dispara:

```text
empresa.com --resolves_to--> IP
empresa.com --has_certificate--> certificado TLS
empresa.com --has_subdomain--> subdomínio
IP --exposes_service--> serviço Shodan
```

7. O grafo passa a exibir a cadeia completa:

```text
email → domain → certificate → subdomain → IP → exposed service
```

---

## 9. Eventos e filas

Use filas por tipo de trabalho, não por fonte.

```text
target.created
collection.requested
collection.completed
collection.failed
observation.normalized
entity.created
entity.merged
relationship.created
correlation.matched
case.report.requested
```

### 9.1 Benefícios

- Novos coletores podem ser adicionados sem alterar o núcleo.
- Falhas ficam isoladas por job.
- É possível priorizar casos, limitar concorrência e aplicar retry.
- O sistema suporta execução assíncrona e long-running.

---

## 10. API sugerida

### 10.1 Casos

```http
POST /api/v1/cases
GET  /api/v1/cases
GET  /api/v1/cases/{case_id}
PATCH /api/v1/cases/{case_id}
DELETE /api/v1/cases/{case_id}
```

### 10.2 Alvos

```http
POST /api/v1/cases/{case_id}/targets
GET  /api/v1/cases/{case_id}/targets
GET  /api/v1/targets/{target_id}
```

### 10.3 Coletas

```http
POST /api/v1/cases/{case_id}/collections
GET  /api/v1/cases/{case_id}/collections
GET  /api/v1/collections/{job_id}
POST /api/v1/collections/{job_id}/cancel
POST /api/v1/collections/{job_id}/retry
```

### 10.4 Evidências e grafo

```http
GET /api/v1/cases/{case_id}/evidence
GET /api/v1/cases/{case_id}/entities
GET /api/v1/cases/{case_id}/relationships
GET /api/v1/cases/{case_id}/graph
GET /api/v1/cases/{case_id}/timeline
```

### 10.5 Relatórios

```http
POST /api/v1/cases/{case_id}/reports
GET  /api/v1/reports/{report_id}
GET  /api/v1/reports/{report_id}/download
```

### 10.6 Fontes

```http
GET /api/v1/sources
GET /api/v1/sources/{source_id}
PATCH /api/v1/sources/{source_id}
POST /api/v1/sources/{source_id}/test
```

---

## 11. Stack tecnológica recomendada

| Camada | Recomendação |
|---|---|
| Linguagem | Python 3.12+ |
| API | FastAPI |
| Validação | Pydantic v2 |
| Filas | Redis Streams no MVP; RabbitMQ ou Kafka em escala |
| Workers | Celery, Arq, RQ ou Dramatiq |
| Banco relacional | PostgreSQL |
| Grafo | Neo4j ou ArangoDB |
| Busca | OpenSearch ou Meilisearch |
| Cache | Redis |
| Armazenamento | S3, MinIO ou equivalente |
| Execução | Docker Compose no MVP; Kubernetes em escala |
| Observabilidade | OpenTelemetry, Prometheus, Grafana, Loki, Sentry |
| Segredos | HashiCorp Vault, AWS Secrets Manager, Doppler ou SOPS |

---

## 12. Estrutura sugerida de repositório

```text
osint-platform/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── cases.py
│   │   │   ├── targets.py
│   │   │   ├── collections.py
│   │   │   ├── evidence.py
│   │   │   ├── graph.py
│   │   │   └── reports.py
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   ├── logging.py
│   │   └── exceptions.py
│   ├── domain/
│   │   ├── models.py
│   │   ├── enums.py
│   │   └── events.py
│   ├── services/
│   │   ├── case_service.py
│   │   ├── orchestrator.py
│   │   ├── normalizer.py
│   │   ├── entity_resolution.py
│   │   ├── correlation.py
│   │   └── reporting.py
│   ├── collectors/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── hibp.py
│   │   ├── intelligence_x.py
│   │   ├── shodan.py
│   │   ├── censys.py
│   │   ├── whois.py
│   │   ├── crtsh.py
│   │   ├── urlscan.py
│   │   └── username_enum.py
│   ├── workers/
│   │   ├── collector_worker.py
│   │   ├── normalizer_worker.py
│   │   └── correlation_worker.py
│   ├── db/
│   │   ├── models.py
│   │   ├── session.py
│   │   └── migrations/
│   └── main.py
├── tests/
├── docker/
├── docs/
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

---

## 13. Regras de robustez

- **Idempotência:** use chave única por `case_id + target + source + adapter_version`.
- **Cache com TTL:** evite consultas repetidas e reduza custo/exposição.
- **Rate limiting por fonte:** respeite limites por chave, IP e plano do provedor.
- **Backoff exponencial:** trate `429`, `5xx`, timeout e erro de autenticação separadamente.
- **Circuit breaker:** desative temporariamente fontes instáveis.
- **Retry seguro:** apenas para erros transitórios.
- **Workers isolados:** coletores não devem acessar diretamente o banco principal.
- **Versionamento de adapters:** preserve `adapter_version` nas evidências.
- **Validação de entrada:** normalize e valide alvos antes de enfileirar.
- **Retenção configurável:** defina expiração por tipo de dado e finalidade.

---

## 14. Segurança, privacidade e conformidade

### 14.1 RBAC sugerido

| Papel | Permissões |
|---|---|
| `admin` | Gerencia usuários, fontes, chaves, políticas e configurações |
| `investigator` | Cria/edita casos e executa coletas autorizadas |
| `analyst` | Visualiza e anota casos, mas não dispara coletas |
| `auditor` | Acessa apenas logs, proveniência e exportações |

### 14.2 Auditoria

Registre, no mínimo:

- Quem executou a ação
- Qual caso foi afetado
- Qual fonte foi consultada
- Qual alvo foi pesquisado
- Quando ocorreu
- De qual IP e dispositivo
- Qual foi o resultado ou erro
- Se houve exportação de dados

### 14.3 Proteção de dados

- Aplique minimização: colete apenas o necessário para a finalidade.
- Defina base legal antes da coleta.
- Use criptografia em trânsito e em repouso.
- Implemente retenção e exclusão configuráveis.
- Separe dados de casos, evidências e identificadores pessoais.
- Restrinja exportações e registre cada download.
- Considere anonimização ou pseudonimização para ambientes de teste.

### 14.4 Conformidade

- LGPD, para operações envolvendo dados de pessoas no Brasil.
- GDPR, quando aplicável a cidadãos ou operações na União Europeia.
- Termos de uso das fontes e APIs.
- `robots.txt` e políticas de crawling.
- Direitos autorais e licenças de dados.
- Restrições contratuais de provedores comerciais de breach intelligence.

---

## 15. MVP recomendado

Comece com um **dossiê por e-mail e domínio**.

### 15.1 Escopo inicial

- Criação de caso
- Entrada de e-mail ou domínio
- Consulta a HIBP
- WHOIS/RDAP
- DNS básico
- Certificados via crt.sh
- Shodan
- urlscan.io
- Intelligence X, se licenciado
- Grafo básico em PostgreSQL
- Exportação JSON

### 15.2 Serviços mínimos

1. API FastAPI
2. Worker Celery/Arq/RQ
3. PostgreSQL
4. Redis
5. Coletores plugáveis
6. Interface web simples

### 15.3 Expansão futura

- Usernames e redes sociais
- Telefonia
- Empresas e CNPJ
- Documentos públicos
- GEOINT
- Busca reversa de imagem
- Correlação avançada
- Relatórios PDF
- Alertas contínuos
- Integração com Maltego

---

## 16. Anti-padrões a evitar

- Não crie um serviço único que chama todas as APIs.
- Não use scraping genérico como fonte primária.
- Não armazene senhas em texto claro ou dumps completos.
- Não confunda dado público com inferência.
- Não permita consultas irrestritas por CPF, nome ou telefone.
- Não exponha chaves de API no frontend.
- Não ignore proveniência e timestamp.
- Não trate coincidências como identificação confirmada.
- Não implemente busca irrestrita de dados pessoais sem controle de finalidade e acesso.

---

## 17. Roadmap técnico

### Fase 1 — Fundação

- Autenticação e RBAC
- Casos e alvos
- PostgreSQL
- Redis
- Dois ou três coletores
- Evidência e auditoria

### Fase 2 — Correlação

- Normalização
- Entity resolution
- Grafo básico
- Timeline
- Regras de correlação

### Fase 3 — Escala

- Filas robustas
- Cache distribuído
- Circuit breakers
- Observabilidade
- Múltiplos workers

### Fase 4 — Produto

- Interface de grafo
- Relatórios
- Alertas
- API pública controlada
- Integrações
- Governança de dados
