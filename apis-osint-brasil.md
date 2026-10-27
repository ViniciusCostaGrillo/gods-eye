# APIs e Fontes OSINT com Foco no Brasil

Lista prática de **fontes oficiais, dados abertos e serviços comerciais** para investigações no Brasil: empresas, CNPJ, processos judiciais, diários oficiais, veículos, placas, documentos, sanções, geografia e transparência.

> **Aviso legal:** consultas a CPF, placa, processo, veículo e dados pessoais geralmente exigem base legal, finalidade legítima, autorização ou contrato com o órgão/provedor. Não utilize scraping não autorizado nem armazene dados além do necessário. A LGPD se aplica.

---

## 1. Empresas, CNPJ e societário

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Receita Federal — Dados Abertos CNPJ** | Base pública completa de CNPJs: razão social, CNAE, endereço, situação cadastral, sócios e estabelecimentos | Gratuito, download de arquivos |
| **API CNPJ Conecta/SERPRO** | Consulta Básica, QSA e Empresa diretamente da Receita Federal | Oficial; requer credenciamento/token |
| **BrasilAPI — CNPJ** | Consulta simplificada de CNPJ com dados públicos | Gratuito |
| **OpenCorporates** | Registros corporativos brasileiros e internacionais | Freemium |
| **Consulta Sócio/Torre** | Empresas, sócios, vínculos societários e histórico | Freemium |
| **CNPJ.ws** | Consulta de CNPJ, CNAE e dados cadastrais | Freemium |
| **ReceitaWS** | Consulta simplificada de CNPJ | Gratuito, com limites |
| **Ministério da Economia/CNPJ aberto** | Dados cadastrais e estruturais para carga própria | Gratuito |
| **JUCESP, JUCERJA, JUCEMG, JUCEPAR** | Registros estaduais, contratos sociais, alterações e certidões | Oficial; varia por estado |
| **Portal da Transparência — Contratos e Convênios** | Contratos federais, convênios, empenhos e fornecedores | Gratuito |

**Endpoint oficial CNPJ (exemplo):**

```http
GET https://apigateway.conectagov.estaleiro.serpro.gov.br/api-cnpj-basica/v2/basica/{cnpj}
```

A API oficial da Receita Federal expõe consultas **Básica**, **QSA** e **Empresa**, incluindo dados não protegidos por sigilo fiscal. [web:51][web:54]

---

## 2. Processos judiciais e jurídico

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **DataJud / CNJ** | Metadados e movimentações processuais unificadas do Judiciário | Oficial; requer credenciamento |
| **PJe** | Processos eletrônicos e documentos processuais | Oficial; acesso controlado |
| **e-SAJ** | Processos e publicações do Tribunal de Justiça de São Paulo | Oficial; consulta pública/autenticada |
| **PJe-Calc** | Cálculos judiciais trabalhistas | Oficial |
| **Consulta Processual TJ** | Consultas públicas por número, parte ou OAB, conforme tribunal | Gratuito |
| **JusBrasil** | Decisões, processos, diários e jurisprudência | Freemium |
| **Consultor Jurídico / ConJur** | Notícias e decisões judiciais | Gratuito |
| **Jurisprudência do STF** | Acórdãos, decisões e informativos do Supremo | Gratuito |
| **Jurisprudência do STJ** | Acórdãos, decisões monocráticas e jurisprudência | Gratuito |
| **Diário da Justiça Eletrônico** | Publicações, intimações, leilões e citações | Gratuito |
| **Escavador** | Processos, empresas, pessoas, diários e vínculos | Freemium |
| **Jusbrasil API / scraping controlado** | Busca de processos e publicações | Comercial |

**Estratégia:** comece pelo **DataJud/CNJ** para metadados processuais e pelo portal de cada TJ para documentos e intimações. O DataJud é a via mais escalável para construir um índice nacional de processos.

---

## 3. Diários oficiais e publicações

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Diário Oficial da União — INLabs** | Busca e API do DOU | Gratuito |
| **DOU — Imprensa Nacional** | Publicações oficiais federais | Gratuito |
| **Diários Oficiais estaduais** | Decretos, editais, intimações e licitações | Gratuito |
| **Querido Diário** | Indexação e busca em diários municipais | Gratuito/open source |
| **Diário Oficial das Cidades** | Publicações municipais | Freemium |
| **Portal da Transparência** | Despesas, contratos, sanções e convênios federais | Gratuito |
| **Portal Nacional de Contratações Públicas — PNCP** | Licitações e contratos públicos | Gratuito |
| **ComprasNet** | Compras e contratações federais | Gratuito |
| **Portal de Compras Públicas** | Licitações e editais | Gratuito |

**Casos de uso:**
- Encontrar menções a uma empresa em editais e sanções.
- Monitorar publicações de falência, recuperação judicial e leilão.
- Correlacionar sócios com contratos públicos.

---

## 4. Veículos, placas e trânsito

### 4.1 Fonte oficial: Senatran/Denatran via SERPRO

O serviço oficial **WSDenatran** consulta veículos, condutores e infrações nas bases Renavam, Renach e Renainf. Ele exige autorização no Denatran, contratação com o SERPRO, certificado digital e credenciais específicas. [web:45][web:47][web:50]

| Consulta | Dados possíveis |
|---|---|
| Veículo por placa | Marca, modelo, ano, situação, restrições e dados cadastrais |
| Veículo por chassi | Identificação e situação do veículo |
| Infrações por placa | Infrações e exigibilidade |
| Roubo/furto por placa | Restrições em aberto |
| Proprietário por CPF/CNPJ | Vínculo entre proprietário e veículo, quando autorizado |
| Condutores/Renach | Dados de habilitação, conforme escopo contratado |

**Documentação oficial:**

```text
https://www.gov.br/conecta/catalogo/apis/wsdenatran
https://wsdenatran.estaleiro.serpro.gov.br/v1/api-example/
```

A API oficial permite consultas por placa, chassi, RENAVAM, CPF/CNPJ do proprietário e verificações de roubo/furto e infrações. [web:46][web:49]

### 4.2 Consulta pública de placa

O serviço **Consultar Placa Veicular** da Senatran permite validar placa, fabricante, estampador, marca/modelo, ano e dados atuais do veículo, mas exige o **QR Code da placa Mercosul**. [web:53]

### 4.3 Serviços comerciais

| Serviço | O que fornece |
|---|---|
| **Consultar Placa API** | Histórico veicular, restrições, leilões, sinistros, recall, FIPE e RENAJUD |
| **DadosAPI** | Veículo por placa/RENAVAM, ficha técnica, valor FIPE |
| **Checkcar** | Histórico, leilão, sinistro e restrições |
| **Olho no Carro** | Histórico e leilões |
| **Tabela FIPE API** | Valor de mercado por marca/modelo/ano |
| **Sinesp Cidadão** | Consulta pública de veículos, quando disponível e autorizada |

**Atenção:** evite APIs não oficiais que prometem dados de proprietário por placa sem contrato ou base legal. Use-as apenas se houver finalidade legítima, contrato e conformidade com LGPD.

---

## 5. Pessoas, CPF e documentos

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Receita Federal — CPF** | Situação cadastral do CPF | Oficial; consulta restrita |
| **TSE — DivulgaCandContas** | Candidatos, bens, prestação de contas e partidos | Gratuito |
| **TSE — Dados Abertos** | Eleições, candidaturas, resultados e prestação de contas | Gratuito |
| **Portal da Transparência — Pessoa Física** | Sanções, convênios e despesas vinculadas a CPF | Gratuito |
| **CEIS/CNEP/CNEP** | Empresas e pessoas sancionadas | Gratuito |
| **CEIS — Cadastro de Empresas Inidôneas e Suspensas** | Sanções administrativas | Gratuito |
| **CNEP — Cadastro Nacional de Empresas Punidas** | Sanções aplicadas por órgãos públicos | Gratuito |
| **CEAF / CEPIM / CNEP** | Inidoneidade, punições e impedimentos | Gratuito |
| **Receita Federal — CND/Certidões** | Certidões negativas e situação fiscal | Oficial |
| **Cartórios — Registro de Imóveis** | Matrículas, propriedades e ônus | Oficial/pago |
| **IPTU e tributos municipais** | Imóveis, débitos e proprietários, conforme município | Oficial |
| **Cartório 24 Horas** | Certidões civis e imobiliárias | Comercial |
| **Registrato / Serasa / SPC / Boa Vista** | Histórico creditício e vínculos | Comercial e restrito |

**Nunca trate consulta de CPF como OSINT irrestrito.** Em geral, é dado pessoal sensível e deve ser acessado apenas com base legal, consentimento, obrigação legal ou contrato adequado.

---

## 6. Sanções, compliance e risco

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **CEIS** | Empresas inidôneas e suspensas | Gratuito |
| **CNEP** | Empresas punidas | Gratuito |
| **CEAF** | Pessoas físicas sancionadas | Gratuito |
| **CEPIM** | Entidades impedidas de celebrar convênios | Gratuito |
| **CNEP/IBAMA** | Embargos e sanções ambientais | Gratuito |
| **TSE — Contas Eleitorais** | Doações, gastos e prestação de contas | Gratuito |
| **CGU — Servidores e Sanções** | Servidores, penalidades e convênios | Gratuito |
| **OFAC / UN / UE Sanctions** | Listas internacionais de sanções | Gratuito |
| **OpenSanctions** | Consolidação de sanções, PEPs e listas de risco | Gratuito/API |
| **World-Check / Dow Jones / LexisNexis** | KYC, PEP, crime financeiro e adverse media | Comercial |

---

## 7. Geografia, endereços e imóveis

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **IBGE — Localidades** | Municípios, estados, regiões, códigos IBGE e população | Gratuito |
| **IBGE Cidades** | Indicadores municipais e estatísticas | Gratuito |
| **ViaCEP** | Consulta de CEP, logradouro, bairro, cidade e UF | Gratuito |
| **BrasilAPI — CEP** | Consulta de CEP com fallback entre fontes | Gratuito |
| **OpenStreetMap Nominatim** | Geocodificação e busca de endereços | Gratuito |
| **OpenStreetMap Overpass** | Consulta estruturada de POIs e infraestrutura | Gratuito |
| **Google Maps Geocoding** | Geocodificação e Places | Freemium |
| **Mapbox** | Geocodificação e mapas | Freemium |
| **INCRA — SIGEF** | Imóveis rurais, certificados e georreferenciamento | Gratuito |
| **CAR — Cadastro Ambiental Rural** | Imóveis rurais e dados ambientais | Gratuito |
| **SIGEF/SNCR** | Cadastro de imóveis rurais | Oficial |
| **Prefeituras — IPTU/GEO** | Cadastro imobiliário municipal e mapas | Varia |

---

## 8. Notícias, redes e mídia

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **Google News RSS** | Notícias por termo, empresa ou pessoa | Gratuito |
| **GDELT** | Notícias globais e eventos | Gratuito |
| **Wayback Machine** | Histórico de páginas e perfis | Gratuito |
| **Common Crawl** | Corpus histórico da web | Gratuito |
| **Bluesky API** | Perfis e posts públicos | Gratuito |
| **Mastodon API** | Perfis e posts públicos | Gratuito |
| **YouTube Data API** | Canais, vídeos e comentários | Freemium |
| **Telegram** | Canais e grupos públicos, conforme ToS | Gratuito |
| **TikTok Research API** | Pesquisa de conteúdo público | Restrito |
| **TinEye / Google Lens** | Busca reversa de imagens | Freemium |

---

## 9. Dados abertos e catálogos nacionais

| Fonte/API | O que fornece | Acesso |
|---|---|---|
| **dados.gov.br** | Catálogo nacional de datasets públicos | Gratuito |
| **API Portal de Dados Abertos** | Busca de datasets, organizações, grupos e tags | Gratuito |
| **Portal Brasileiro de Dados Abertos** | Milhares de bases públicas | Gratuito |
| **IBGE SIDRA** | Séries estatísticas e tabelas | Gratuito |
| **IPEA Data** | Indicadores econômicos e sociais | Gratuito |
| **Banco Central — Dados Abertos** | Câmbio, crédito, instituições e séries | Gratuito |
| **ANATEL** | Outorgas, estações e espectro | Gratuito |
| **ANEEL** | Geração, distribuição e outorgas elétricas | Gratuito |
| **ANP** | Postos, agências e dados de combustíveis | Gratuito |
| **ANVISA** | Medicamentos, empresas e registros sanitários | Gratuito |
| **INPI** | Marcas, patentes e desenhos industriais | Gratuito |
| **SUSEP** | Seguradoras, produtos e corretores | Gratuito |
| **BACEN — IF.data** | Instituições financeiras e dados regulatórios | Gratuito |
| **CVM** | Companhias abertas, fundos e ofertas públicas | Gratuito |
| **TSE** | Eleições, candidatos e partidos | Gratuito |

A API do Portal Brasileiro de Dados Abertos permite buscar, listar e detalhar datasets, organizações, grupos e tags em formato REST/JSON. [web:56]

---

## 10. Prioridade para o agregador brasileiro

### MVP recomendado

1. **CNPJ** — Receita Federal aberta + BrasilAPI.
2. **Processos** — DataJud/CNJ + portais dos TJs.
3. **Diários Oficiais** — DOU/INLabs + Querido Diário.
4. **Sanções** — CEIS, CNEP, CEAF, CEPIM e OpenSanctions.
5. **Eleições** — TSE DivulgaCandContas.
6. **Transparência** — Portal da Transparência e PNCP.
7. **CEP/endereço** — ViaCEP, BrasilAPI e Nominatim.
8. **Geografia** — IBGE.
9. **Marcas e patentes** — INPI.
10. **Notícias** — Google News RSS e GDELT.

### Veículos

Para veículos, use **apenas**:

- **Senatran/Denatran via SERPRO**, se você tiver contrato e autorização.
- **Consulta pública de placa Mercosul**, quando o usuário tiver o QR Code.
- **Provedores comerciais licenciados**, com contrato, finalidade e compliance definidos.

Não construa um coletor que faça scraping de sistemas de trânsito ou exponha dados de proprietário sem autorização.

---

## 11. Modelo de dados adicional para Brasil

```text
BrazilianCompany
  cnpj, razao_social, nome_fantasia, situacao_cadastral,
  data_abertura, cnae_principal, cnaes_secundarios,
  endereco, municipio, uf, capital_social, natureza_juridica

BrazilianPerson
  nome, cpf_hash, data_nascimento_faixa, municipio, uf,
  pep_flag, sanctions[]

LegalCase
  numero_processo, tribunal, classe, assunto, orgao,
  partes[], movimentacoes[], valor_causa, status

Vehicle
  placa_hash, renavam_hash, chassi_hash, marca, modelo,
  ano_fabricacao, ano_modelo, cor, combustivel, situacao,
  restricoes[], leiloes[], sinistros[]

OfficialPublication
  diario, data_publicacao, caderno, pagina, texto,
  url_original, entidade_mencionada

Sanction
  tipo, orgao_sancionador, numero_processo, data_inicio,
  data_fim, fundamento_legal, entidade_sancionada
```

---

## 12. Regras de compliance no Brasil

- **LGPD:** defina base legal antes de coletar ou tratar dados pessoais.
- **Finalidade:** registre a finalidade do caso antes da consulta.
- **Minimização:** não armazene CPF completo; prefira hash + últimos dígitos quando possível.
- **Retenção:** defina prazo de exclusão por tipo de dado.
- **Acesso:** restrinja consulta de CPF, processo, veículo e sanções por papel e permissão.
- **Auditoria:** registre quem consultou, quando, por qual caso e com qual finalidade.
- **Fontes oficiais primeiro:** priorize gov.br, tribunais, TSE, IBGE, Receita Federal e portais de transparência.
- **Contratos:** para Denatran/SERPRO, Receita Federal via Conecta e bases comerciais, formalize acesso e limites de uso.

---

## 13. Exemplo de fluxo: empresa brasileira

**Alvo:** CNPJ `00.000.000/0001-91`

1. Consulta CNPJ na Receita Federal/BrasilAPI.
2. Extrai razão social, CNAE, endereço, município e QSA.
3. Consulta processos no DataJud e portais dos TJs.
4. Busca a empresa e sócios em DOU, diários estaduais e Querido Diário.
5. Consulta CEIS, CNEP, CEAF, CEPIM e sanções ambientais.
6. Consulta contratos e licitações no Portal da Transparência e PNCP.
7. Busca notícias via Google News RSS e GDELT.
8. Consulta marcas e patentes no INPI.
9. Gera grafo:

```text
CNPJ --has_qsa--> Pessoa
CNPJ --appears_in--> Diário Oficial
CNPJ --has_case--> Processo
CNPJ --has_sanction--> Sanção
CNPJ --has_contract--> Contrato público
Pessoa --is_pep--> PEP
Pessoa --owns--> Outro CNPJ
```

---

## 14. Exemplo de fluxo: veículo por placa

**Alvo:** placa Mercosul.

1. Verifique se o usuário possui **QR Code da placa**.
2. Se sim, consulte o serviço público **Consultar Placa Veicular** da Senatran.
3. Se houver contrato com SERPRO/Denatran, consulte WSDenatran para:
   - Dados do veículo
   - Restrições
   - Infrações
   - Roubo/furto
4. Consulte leilões, sinistros e histórico apenas por provedores licenciados.
5. Registre evidência, finalidade, operador e base legal.

**Fluxo seguro:**

```text
Placa + QR Code → Senatran pública
Placa + contrato SERPRO → WSDenatran
Placa + provedor licenciado → histórico comercial
Placa sozinha → não inferir proprietário sem base legal
```
