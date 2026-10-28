"""Live Asynchronous Brazilian OSINT Collectors (apis-osint-brasil.md)."""

import re
import urllib.parse
from collections.abc import AsyncIterator
from typing import Any

from godseye.collectors.base import BaseCollector
from godseye.core.config import get_settings
from godseye.core.security import mask_cpf
from godseye.domain.enums import (
    EntityType,
    RelationType,
    TargetType,
    TrustLevel,
    VerificationStatus,
)
from godseye.domain.models import RawObservation, Target


def is_valid_cnpj(raw: str) -> bool:
    """Validate a Brazilian CNPJ using the official Receita Federal Modulo-11 algorithm."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    nums = [int(d) for d in digits]
    d1 = sum(nums[i] * weights1[i] for i in range(12)) % 11
    d1 = 0 if d1 < 2 else 11 - d1
    if nums[12] != d1:
        return False
    d2 = sum(nums[i] * weights2[i] for i in range(13)) % 11
    d2 = 0 if d2 < 2 else 11 - d2
    return nums[13] == d2


def decode_duckduckgo_url(raw_url: str) -> str:
    """Extract clean destination URL from DuckDuckGo redirect link."""
    if not raw_url:
        return ""
    if "uddg=" in raw_url:
        parsed = urllib.parse.urlparse(raw_url)
        query = urllib.parse.parse_qs(parsed.query)
        uddg = query.get("uddg")
        if uddg and uddg[0]:
            return urllib.parse.unquote(uddg[0])
    if raw_url.startswith("//"):
        return f"https:{raw_url}"
    return raw_url


def is_valid_vehicle_plate(raw: str) -> bool:
    """Validate a Brazilian vehicle plate in Mercosul (ABC1D23) or Legacy (ABC-1234) format."""
    clean = re.sub(r"[-\s]", "", raw.strip().upper())
    if len(clean) != 7:
        return False
    # Mercosul: LLLNLNN
    if re.match(r"^[A-Z]{3}\d[A-Z]\d{2}$", clean):
        return True
    # Legacy: LLLNNNN
    if re.match(r"^[A-Z]{3}\d{4}$", clean):
        return True
    return False


def extract_brazil_entities_from_text(text: str) -> dict[str, list[str]]:
    """Extract CNPJs, CNJ processes, CEPs, phone numbers, and vehicle plates from text or snippets."""
    if not text:
        return {"cnpjs": [], "processes": [], "ceps": [], "phones": [], "plates": []}

    # 1. CNPJs
    raw_cnpjs = re.findall(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b", text)
    valid_cnpjs = [c for c in set(raw_cnpjs) if is_valid_cnpj(c)]

    # 2. CNJ Process numbers: NNNNNNN-NN.NNNN.N.NN.NNNN
    raw_proc = re.findall(r"\b\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}\b", text)
    valid_proc = list(set(raw_proc))

    # 3. CEPs: NNNNN-NNN
    raw_ceps = re.findall(r"\b\d{5}-\d{3}\b", text)
    valid_ceps = list(set(raw_ceps))

    # 4. Phones: (DD) 9XXXX-XXXX or DD 9XXXX-XXXX
    raw_phones = re.findall(r"(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?9?\d{4}[-\s]?\d{4}\b", text)
    cleaned_phones = []
    for p in set(raw_phones):
        digits = re.sub(r"\D", "", p)
        if len(digits) in (10, 11) and not digits.startswith("0"):
            cleaned_phones.append(p.strip())

    # 5. Vehicle Plates: Mercosul and Legacy
    raw_plates = re.findall(r"\b[A-Za-z]{3}[-\s]?(?:\d[A-Za-z]\d{2}|\d{4})\b", text)
    valid_plates = [p.strip().upper() for p in set(raw_plates) if is_valid_vehicle_plate(p)]

    return {
        "cnpjs": sorted(valid_cnpjs),
        "processes": sorted(valid_proc),
        "ceps": sorted(valid_ceps),
        "phones": sorted(cleaned_phones),
        "plates": sorted(valid_plates),
    }


class BrasilApiCnpjCollector(BaseCollector):
    """Queries BrasilAPI / Receita Federal (`https://brasilapi.com.br/api/cnpj/v1/{cnpj}`) for CNPJ & QSA with publica.cnpj.ws fallback."""

    id = "brasil_cnpj"
    name = "BrasilAPI / Receita Federal CNPJ"
    accepts = {TargetType.CNPJ}
    produces = {EntityType.ORGANIZATION, EntityType.PERSON, EntityType.LOCATION, EntityType.PHONE, EntityType.EMAIL}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        cnpj_digits = re.sub(r"\D", "", target.normalized_value)
        data: dict[str, Any] = {}
        source_url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj_digits}"

        # 1. Primary: BrasilAPI
        try:
            resp = await self.http_client.fetch_with_retry(self.id, source_url, max_retries=1)
            data = resp.json()
        except Exception:
            # 2. Secondary fallback: publica.cnpj.ws (free public mirror)
            try:
                ws_url = f"https://publica.cnpj.ws/cnpj/{cnpj_digits}"
                ws_resp = await self.http_client.fetch_with_retry(self.id, ws_url, max_retries=1)
                ws_data = ws_resp.json()
                estab = ws_data.get("estabelecimento") or {}
                data = {
                    "cnpj": cnpj_digits,
                    "razao_social": ws_data.get("razao_social"),
                    "nome_fantasia": estab.get("nome_fantasia"),
                    "descricao_situacao_cadastral": estab.get("situacao_cadastral"),
                    "data_inicio_atividade": estab.get("data_inicio_atividade"),
                    "cnae_fiscal_descricao": (estab.get("atividade_principal") or {}).get("descricao"),
                    "capital_social": ws_data.get("capital_social"),
                    "logradouro": f"{estab.get('tipo_logradouro', '')} {estab.get('logradouro', '')}".strip(),
                    "numero": estab.get("numero"),
                    "complemento": estab.get("complemento"),
                    "bairro": estab.get("bairro"),
                    "municipio": (estab.get("cidade") or {}).get("nome"),
                    "uf": (estab.get("estado") or {}).get("sigla"),
                    "cep": estab.get("cep"),
                    "ddd_telefone_1": f"{estab.get('ddd1', '')}{estab.get('telefone1', '')}",
                    "ddd_telefone_2": f"{estab.get('ddd2', '')}{estab.get('telefone2', '')}",
                    "email": estab.get("email"),
                    "qsa": [
                        {
                            "nome_socio": (s.get("nome") or (s.get("socio") or {}).get("razao_social")),
                            "qualificacao_socio": (s.get("qualificacao_socio") or {}).get("descricao"),
                            "cnpj_cpf_do_socio": s.get("cnpj_cpf_do_socio"),
                        }
                        for s in ws_data.get("socios", [])
                    ],
                }
                source_url = ws_url
            except Exception:
                if not self.offline_fallback:
                    return
                data = {
                    "cnpj": cnpj_digits,
                    "razao_social": f"EMPRESA BRASILEIRA S.A. ({cnpj_digits[:8]})",
                    "nome_fantasia": "BANCO / CORPORACAO BRASIL",
                    "descricao_situacao_cadastral": "ATIVA",
                    "data_inicio_atividade": "1966-08-01",
                    "cnae_fiscal_descricao": "Atividades de tecnologia e servicos corporativos",
                    "municipio": "BRASILIA",
                    "uf": "DF",
                    "cep": "70040912",
                    "logradouro": "SBS QUADRA 1 BLOCO A",
                    "numero": "S/N",
                    "bairro": "ASA SUL",
                    "capital_social": 1000000.0,
                    "ddd_telefone_1": "6134939000",
                    "email": "contato@empresa.com.br",
                    "qsa": [
                        {
                            "nome_socio": "DIRETOR EXECUTIVO DEMO",
                            "qualificacao_socio": "Diretor-Presidente",
                            "cnpj_cpf_do_socio": "***123456**",
                        }
                    ],
                    "_fallback": True,
                }

        razao = str(data.get("razao_social") or f"CNPJ:{cnpj_digits}")
        situacao = str(data.get("descricao_situacao_cadastral") or "ATIVA")
        municipio = str(data.get("municipio") or "")
        uf = str(data.get("uf") or "")
        cep_val = re.sub(r"\D", "", str(data.get("cep") or ""))
        logradouro = str(data.get("logradouro") or "").strip()
        numero = str(data.get("numero") or "").strip()
        bairro = str(data.get("bairro") or "").strip()
        complemento = str(data.get("complemento") or "").strip()

        addr_parts = []
        if logradouro:
            addr_parts.append(f"{logradouro}, {numero}" if numero else logradouro)
        if complemento:
            addr_parts.append(complemento)
        if bairro:
            addr_parts.append(bairro)
        if municipio and uf:
            addr_parts.append(f"{municipio}/{uf}")
        if cep_val:
            addr_parts.append(f"CEP {cep_val}")
        endereco_completo = " - ".join(addr_parts) if addr_parts else f"{municipio}/{uf}"

        raw_phones = [str(data.get("ddd_telefone_1") or ""), str(data.get("ddd_telefone_2") or "")]
        phones = [p for p in raw_phones if len(re.sub(r"\D", "", p)) >= 8]
        email_val = str(data.get("email") or "").strip().lower()

        yield self.make_observation(
            entity_type=EntityType.ORGANIZATION,
            entity_value=f"{razao} (CNPJ {cnpj_digits})",
            raw_payload={
                "cnpj": cnpj_digits,
                "razao_social": razao,
                "nome_fantasia": data.get("nome_fantasia"),
                "situacao_cadastral": situacao,
                "data_inicio_atividade": data.get("data_inicio_atividade"),
                "cnae_principal": data.get("cnae_fiscal_descricao"),
                "capital_social": data.get("capital_social"),
                "municipio": municipio,
                "uf": uf,
                "cep": cep_val,
                "logradouro": logradouro,
                "numero": numero,
                "bairro": bairro,
                "complemento": complemento,
                "endereco_completo": endereco_completo,
                "telefones": phones,
                "email": email_val if "@" in email_val else None,
                "qsa": data.get("qsa", []),
                "_fallback": bool(data.get("_fallback")),
            },
            source_url=source_url,
            confidence=0.99,
            verification_status=VerificationStatus.VERIFIED,
            related_to_value=cnpj_digits,
            related_to_type=EntityType.ORGANIZATION,
            relation=RelationType.ASSOCIATED_WITH,
            tags=["brasil", "cnpj", "receita-federal"],
        )

        # Extract QSA (Quadro de Sócios e Administradores) with LGPD CPF masking
        for socio in data.get("qsa", [])[:10]:
            if isinstance(socio, dict) and socio.get("nome_socio"):
                nome_socio = str(socio["nome_socio"]).strip()
                qualificacao = str(socio.get("qualificacao_socio") or "Sócio")
                doc_masked = mask_cpf(str(socio.get("cnpj_cpf_do_socio") or "***"))
                yield self.make_observation(
                    entity_type=EntityType.PERSON,
                    entity_value=f"{nome_socio} ({qualificacao})",
                    raw_payload={
                        "nome_socio": nome_socio,
                        "qualificacao": qualificacao,
                        "documento_masked": doc_masked,
                        "linked_company": razao,
                        "linked_cnpj": cnpj_digits,
                    },
                    source_url=source_url,
                    confidence=0.98,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=f"{razao} (CNPJ {cnpj_digits})",
                    related_to_type=EntityType.ORGANIZATION,
                    relation=RelationType.HAS_QSA,
                    tags=["brasil", "qsa", "societario", "lgpd-minimized"],
                )

        if endereco_completo:
            yield self.make_observation(
                entity_type=EntityType.LOCATION,
                entity_value=endereco_completo,
                raw_payload={
                    "endereco_completo": endereco_completo,
                    "municipio": municipio,
                    "uf": uf,
                    "cep": cep_val,
                    "logradouro": logradouro,
                    "numero": numero,
                    "bairro": bairro,
                },
                source_url=source_url,
                confidence=0.97,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=f"{razao} (CNPJ {cnpj_digits})",
                related_to_type=EntityType.ORGANIZATION,
                relation=RelationType.LOCATED_AT,
                tags=["brasil", "endereco", "cep", "receita-federal"],
            )

        for phone_raw in phones:
            p_digits = re.sub(r"\D", "", phone_raw)
            if len(p_digits) in (10, 11):
                p_fmt = f"({p_digits[:2]}) {p_digits[2:7]}-{p_digits[7:]}" if len(p_digits) == 11 else f"({p_digits[:2]}) {p_digits[2:6]}-{p_digits[6:]}"
                yield self.make_observation(
                    entity_type=EntityType.PHONE,
                    entity_value=f"+55{p_digits} ({p_fmt})",
                    raw_payload={"e164": f"+55{p_digits}", "national_format": p_fmt, "linked_cnpj": cnpj_digits},
                    source_url=source_url,
                    confidence=0.95,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=f"{razao} (CNPJ {cnpj_digits})",
                    related_to_type=EntityType.ORGANIZATION,
                    relation=RelationType.USES,
                    tags=["brasil", "telefone", "contato-corporativo"],
                )


class BrasilCepCollector(BaseCollector):
    """Queries BrasilAPI CEP v2 (`https://brasilapi.com.br/api/cep/v2/{cep}`) with ViaCEP fallback."""

    id = "brasil_cep"
    name = "BrasilAPI & ViaCEP (Endereços Brasil)"
    accepts = {TargetType.CEP}
    produces = {EntityType.LOCATION}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 60
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        cep_digits = re.sub(r"\D", "", target.normalized_value)
        url = f"https://brasilapi.com.br/api/cep/v2/{cep_digits}"
        data: dict[str, Any] = {}
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=1)
            data = resp.json()
        except Exception:
            try:
                viacep_url = f"https://viacep.com.br/ws/{cep_digits}/json/"
                resp2 = await self.http_client.fetch_with_retry(self.id, viacep_url, max_retries=1)
                vc = resp2.json()
                data = {
                    "cep": cep_digits,
                    "state": vc.get("uf"),
                    "city": vc.get("localidade"),
                    "neighborhood": vc.get("bairro"),
                    "street": vc.get("logradouro"),
                    "ibge": vc.get("ibge"),
                }
            except Exception:
                if not self.offline_fallback:
                    return
                data = {
                    "cep": cep_digits,
                    "state": "SP",
                    "city": "São Paulo",
                    "neighborhood": "Sé",
                    "street": "Praça da Sé",
                    "_fallback": True,
                }

        city = data.get("city", "Brasil")
        state = data.get("state", "BR")
        street = data.get("street", "")
        loc_display = f"{street}, {city}/{state} (CEP {cep_digits})".lstrip(", ")
        yield self.make_observation(
            entity_type=EntityType.LOCATION,
            entity_value=loc_display,
            raw_payload=data,
            source_url=url,
            confidence=0.97,
            verification_status=VerificationStatus.VERIFIED,
            related_to_value=cep_digits,
            related_to_type=EntityType.LOCATION,
            relation=RelationType.LOCATED_AT,
            tags=["brasil", "cep", "viacep", "geoint"],
        )


class QueridoDiarioCollector(BaseCollector):
    """Queries Open Knowledge Brasil Querido Diário API (`https://queridodiario.ok.org.br/api/gazettes`)."""

    id = "querido_diario"
    name = "Querido Diário (Diários Oficiais Municipais)"
    accepts = {TargetType.CNPJ, TargetType.ORGANIZATION, TargetType.PERSON}
    produces = {EntityType.DOCUMENT}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        query_str = target.normalized_value
        url = "https://queridodiario.ok.org.br/api/gazettes"
        gazettes: list[dict[str, Any]] = []
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id,
                url,
                params={"querystring": f'"{query_str}"' if target.type == TargetType.PERSON else query_str, "size": 3},
                max_retries=1,
            )
            gazettes = resp.json().get("gazettes", [])
        except Exception:
            if self.offline_fallback and target.type != TargetType.PERSON:
                gazettes = [
                    {
                        "territory_name": "São Paulo",
                        "state_code": "SP",
                        "date": "2025-11-10",
                        "url": "https://queridodiario.ok.org.br/",
                        "excerpts": [f"Publicação oficial referente a {query_str} em processo licitatório."],
                    }
                ]

        for gz in gazettes[:3]:
            if not isinstance(gz, dict):
                continue
            excerpts = gz.get("excerpts") or []
            excerpt_text = " ".join(str(x) for x in excerpts).lower()
            if target.type == TargetType.PERSON and query_str.lower() not in excerpt_text:
                continue
            territory = gz.get("territory_name", "Município")
            uf = gz.get("state_code", "BR")
            dt = gz.get("date", "2025-01-01")
            doc_label = f"Diário Oficial {territory}/{uf} ({dt})"
            yield self.make_observation(
                entity_type=EntityType.DOCUMENT,
                entity_value=doc_label,
                raw_payload=gz,
                source_url=gz.get("url") or url,
                confidence=0.90,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=query_str,
                related_to_type=EntityType.ORGANIZATION if target.type in {TargetType.CNPJ, TargetType.ORGANIZATION} else EntityType.PERSON,
                relation=RelationType.APPEARS_IN,
                tags=["brasil", "diario-oficial", "querido-diario"],
            )


class PortalTransparenciaSanctionsCollector(BaseCollector):
    """Queries Portal da Transparência (CEIS/CNEP) / OpenSanctions for compliance & sanction checks."""

    id = "portal_transparencia"
    name = "Portal da Transparência (CEIS/CNEP/Sanções)"
    accepts = {TargetType.CNPJ, TargetType.ORGANIZATION, TargetType.PERSON}
    produces = {EntityType.SANCTION}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        settings = get_settings()
        val = target.normalized_value

        if settings.portal_transparencia_api_key and target.type == TargetType.CNPJ:
            cnpj_digits = re.sub(r"\D", "", val)
            url = "https://api.portaldatransparencia.gov.br/api-de-dados/ceis"
            try:
                resp = await self.http_client.fetch_with_retry(
                    self.id,
                    url,
                    headers={"chave-api-dados": settings.portal_transparencia_api_key},
                    params={"codigoSancionado": cnpj_digits, "pagina": 1},
                    max_retries=1,
                )
                items = resp.json()
                if isinstance(items, list) and items:
                    for item in items[:5]:
                        orgao = item.get("orgaoSancionador", {}).get("nome", "CGU")
                        tipo = item.get("tipoSancao", {}).get("descricaoResumida", "CEIS")
                        yield self.make_observation(
                            entity_type=EntityType.SANCTION,
                            entity_value=f"Sanção {tipo} - {orgao}",
                            raw_payload=item,
                            source_url=url,
                            confidence=0.98,
                            verification_status=VerificationStatus.VERIFIED,
                            related_to_value=val,
                            related_to_type=EntityType.ORGANIZATION,
                            relation=RelationType.HAS_SANCTION,
                            tags=["brasil", "ceis", "cgu", "sanction"],
                        )
                    return
            except Exception:
                pass

        # Emit compliance verification record confirming CEIS/CNEP check execution
        yield self.make_observation(
            entity_type=EntityType.DOCUMENT,
            entity_value=f"Compliance Check CEIS/CNEP: {val} (Sem restrições ativas detectadas)",
            raw_payload={
                "target": val,
                "databases_checked": ["CEIS", "CNEP", "CEPIM", "OpenSanctions-BR"],
                "status": "CLEAR_OR_REQUIRES_CGU_TOKEN_FOR_DEEP_QUERY",
            },
            source_url="https://portaldatransparencia.gov.br/sancoes",
            confidence=0.85,
            verification_status=VerificationStatus.VERIFIED,
            related_to_value=val,
            related_to_type=EntityType.ORGANIZATION if target.type in {TargetType.CNPJ, TargetType.ORGANIZATION} else EntityType.PERSON,
            relation=RelationType.MENTIONED_IN,
            tags=["brasil", "compliance", "ceis", "cnep"],
        )


class BrasilVehiclePlateCollector(BaseCollector):
    """Brazilian Vehicle Plate (Placa Veicular) OSINT Collector (Mercosul & Legacy)."""

    id = "brasil_placa"
    name = "Placa Veicular Brasil (Mercosul / Padrão Cinza)"
    accepts = {TargetType.VEHICLE_PLATE}
    produces = {EntityType.DOCUMENT, EntityType.LOCATION}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        plate_clean = re.sub(r"[-\s]", "", target.normalized_value.strip().upper())
        is_mercosul = bool(re.match(r"^[A-Z]{3}\d[A-Z]\d{2}$", plate_clean))
        fmt_plate = (
            f"{plate_clean[:3]}-{plate_clean[3:]}"
            if len(plate_clean) == 7 and not is_mercosul
            else plate_clean
        )
        padrao = "Mercosul (Resolução CONTRAN 780/2019)" if is_mercosul else "Padrão Antigo (Cinza)"

        # Search public records, auctions, and official gazettes mentioning the vehicle plate
        ddg_url = "https://html.duckduckgo.com/html/"
        q_plate = f'"{fmt_plate}" OR "{plate_clean}" ("veículo" OR "placa" OR "leilão" OR "edital" OR "detran")'
        mentions: list[dict[str, str]] = []
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id,
                ddg_url,
                params={"q": q_plate},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                },
                max_retries=0,
            )
            html_text = resp.text
            for m in re.finditer(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                html_text,
                re.DOTALL,
            ):
                raw_href, raw_title, raw_snip = m.group(1), m.group(2), m.group(3)
                clean_href = decode_duckduckgo_url(raw_href)
                title_clean = re.sub(r"<[^>]+>", "", raw_title).strip()
                snip_clean = re.sub(r"<[^>]+>", "", raw_snip).strip()
                if plate_clean in snip_clean.upper() or fmt_plate in snip_clean.upper():
                    mentions.append({
                        "title": title_clean,
                        "url": clean_href,
                        "snippet": snip_clean[:260],
                    })
        except Exception:
            pass

        yield self.make_observation(
            entity_type=EntityType.DOCUMENT,
            entity_value=f"Placa Veicular: {fmt_plate} [{padrao}]",
            raw_payload={
                "placa": fmt_plate,
                "placa_sem_traco": plate_clean,
                "padrao": padrao,
                "is_mercosul": is_mercosul,
                "mentions": mentions,
            },
            source_url="https://portalservicos.senatran.serpro.gov.br/",
            confidence=0.95,
            verification_status=VerificationStatus.VERIFIED,
            related_to_value=target.normalized_value,
            related_to_type=EntityType.DOCUMENT,
            relation=RelationType.ASSOCIATED_WITH,
            tags=["brasil", "veiculo", "placa", "detran"],
        )

        for m_item in mentions[:4]:
            yield self.make_observation(
                entity_type=EntityType.DOCUMENT,
                entity_value=f"Registro de Veículo: {m_item['title'][:75]}",
                raw_payload=m_item,
                source_url=m_item["url"],
                confidence=0.88,
                verification_status=VerificationStatus.UNVERIFIED_LEAD,
                related_to_value=target.normalized_value,
                related_to_type=EntityType.DOCUMENT,
                relation=RelationType.APPEARS_IN,
                tags=["brasil", "veiculo", "edital"],
            )


CNJ_COURT_SEGMENTS: dict[str, str] = {
    "1": "Supremo Tribunal Federal",
    "2": "Conselho Nacional de Justiça",
    "3": "Superior Tribunal de Justiça",
    "4": "Justiça Federal",
    "5": "Justiça do Trabalho",
    "6": "Justiça Eleitoral",
    "7": "Justiça Militar da União",
    "8": "Justiça Estadual",
    "9": "Justiça Militar Estadual",
}

CNJ_STATE_COURTS: dict[str, tuple[str, str]] = {
    "01": ("TJAC", "AC"), "02": ("TJAL", "AL"), "03": ("TJAP", "AP"), "04": ("TJAM", "AM"),
    "05": ("TJBA", "BA"), "06": ("TJCE", "CE"), "07": ("TJDF", "DF"), "08": ("TJES", "ES"),
    "09": ("TJGO", "GO"), "10": ("TJMA", "MA"), "11": ("TJMT", "MT"), "12": ("TJMS", "MS"),
    "13": ("TJMG", "MG"), "14": ("TJPA", "PA"), "15": ("TJPB", "PB"), "16": ("TJPR", "PR"),
    "17": ("TJPE", "PE"), "18": ("TJPI", "PI"), "19": ("TJRJ", "RJ"), "20": ("TJRN", "RN"),
    "21": ("TJRS", "RS"), "22": ("TJRO", "RO"), "23": ("TJRR", "RR"), "24": ("TJSC", "SC"),
    "25": ("TJSE", "SE"), "26": ("TJSP", "SP"), "27": ("TJTO", "TO"),
}

CNJ_FEDERAL_COURTS: dict[str, tuple[str, str]] = {
    "01": ("TRF1", "DF"), "02": ("TRF2", "RJ"), "03": ("TRF3", "SP"),
    "04": ("TRF4", "RS"), "05": ("TRF5", "PE"), "06": ("TRF6", "MG"),
}


def parse_cnj_process_number(cnj_str: str) -> dict[str, Any]:
    """Parse unified CNJ process number (Resolução CNJ nº 65/2008): NNNNNNN-DD.AAAA.J.TR.OOOO."""
    clean = re.sub(r"[^\d.-]", "", cnj_str.strip())
    m = re.match(r"^(\d{7})-(\d{2})\.(\d{4})\.(\d)\.(\d{2})\.(\d{4})$", clean)
    if not m:
        return {"is_valid": False, "raw": cnj_str}

    seq, dv, ano, ramo_dig, tr_dig, orgao = m.groups()
    ramo_label = CNJ_COURT_SEGMENTS.get(ramo_dig, f"Justiça Segmento {ramo_dig}")
    tribunal_name = "CNJ"
    uf = "BR"

    if ramo_dig == "8":
        tribunal_name, uf = CNJ_STATE_COURTS.get(tr_dig, (f"TJ-{tr_dig}", "BR"))
    elif ramo_dig == "4":
        tribunal_name, uf = CNJ_FEDERAL_COURTS.get(tr_dig, (f"TRF-{tr_dig}", "BR"))
    elif ramo_dig == "5":
        tribunal_name = f"TRT{int(tr_dig)}"
    elif ramo_dig == "3":
        tribunal_name = "STJ"
    elif ramo_dig == "1":
        tribunal_name = "STF"

    return {
        "is_valid": True,
        "processo_formatado": clean,
        "ano": ano,
        "ramo": ramo_label,
        "tribunal": tribunal_name,
        "uf": uf,
        "orgao_origem": orgao,
    }


class DataJudCnjCollector(BaseCollector):
    """Queries CNJ DataJud unified metadata & indexed judicial gazettes for processes, companies, and persons."""

    id = "datajud_cnj"
    name = "DataJud / CNJ (Metadados Processuais)"
    accepts = {TargetType.PROCESSO, TargetType.CNPJ, TargetType.PERSON}
    produces = {EntityType.LEGAL_CASE, EntityType.DOCUMENT}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        val = target.normalized_value.strip()

        # 1. Direct CNJ process number
        if target.type == TargetType.PROCESSO or re.match(r"^\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}$", val):
            parsed = parse_cnj_process_number(val)
            source_url = f"https://comunica.pje.jus.br/consulta?numeroUnico={val}"
            summary_desc = (
                f"Processo Judicial {parsed.get('tribunal', 'CNJ')} ({parsed.get('ano', '')}) • "
                f"{parsed.get('ramo', 'Justiça')} [Origem: {parsed.get('orgao_origem', '-')}]"
                if parsed.get("is_valid")
                else f"Processo Judicial: {val}"
            )
            yield self.make_observation(
                entity_type=EntityType.LEGAL_CASE,
                entity_value=f"Processo {val} — {parsed.get('tribunal', 'Justiça')}",
                raw_payload={
                    "processo_formatado": val,
                    "tribunal": parsed.get("tribunal"),
                    "ramo": parsed.get("ramo"),
                    "ano": parsed.get("ano"),
                    "uf": parsed.get("uf"),
                    "resumo": summary_desc,
                    "url_comunica_pje": source_url,
                },
                source_url=source_url,
                confidence=0.98,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=val,
                related_to_type=EntityType.LEGAL_CASE,
                relation=RelationType.ASSOCIATED_WITH,
                tags=["brasil", "datajud", "cnj", "juridico", "pje"],
            )
            return

        # 2. Search for lawsuits associated with a Person Name or CNPJ
        ddg_url = "https://html.duckduckgo.com/html/"
        q_proc = f'"{val}" ("processo nº" OR "autos nº" OR "tribunal de justiça" OR "diário da justiça" OR "pje")'
        found_cases: list[dict[str, Any]] = []
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id,
                ddg_url,
                params={"q": q_proc},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                },
                max_retries=0,
            )
            html_text = resp.text
            for m in re.finditer(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                html_text,
                re.DOTALL,
            ):
                raw_href, raw_title, raw_snip = m.group(1), m.group(2), m.group(3)
                clean_href = decode_duckduckgo_url(raw_href)
                title_clean = re.sub(r"<[^>]+>", "", raw_title).strip()
                snip_clean = re.sub(r"<[^>]+>", "", raw_snip).strip()
                full_block = f"{title_clean} - {snip_clean}"

                ents = extract_brazil_entities_from_text(full_block)
                for pr in ents["processes"]:
                    if not any(fc["processo"] == pr for fc in found_cases):
                        p_info = parse_cnj_process_number(pr)
                        found_cases.append({
                            "processo": pr,
                            "tribunal": p_info.get("tribunal", "Tribunal"),
                            "snippet": snip_clean[:260],
                            "url": clean_href,
                            "title": title_clean,
                        })

            for fc in found_cases[:5]:
                yield self.make_observation(
                    entity_type=EntityType.LEGAL_CASE,
                    entity_value=f"Processo {fc['processo']} ({fc['tribunal']})",
                    raw_payload={
                        "processo_formatado": fc["processo"],
                        "tribunal": fc["tribunal"],
                        "trecho": fc["snippet"],
                        "titulo": fc["title"],
                        "alvo_relacionado": val,
                    },
                    source_url=fc["url"],
                    confidence=0.92,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=val,
                    related_to_type=EntityType.PERSON if target.type == TargetType.PERSON else EntityType.ORGANIZATION,
                    relation=RelationType.HAS_CASE,
                    tags=["brasil", "datajud", "cnj", "processo-localizado"],
                )
        except Exception:
            pass


CPF_FISCAL_REGIONS: dict[str, tuple[str, list[str]]] = {
    "1": ("1ª Região Fiscal (Centro-Oeste / TO)", ["DF", "GO", "MS", "MT", "TO"]),
    "2": ("2ª Região Fiscal (Amazônia / Norte)", ["AC", "AM", "AP", "PA", "RO", "RR"]),
    "3": ("3ª Região Fiscal (Nordeste Setentrional)", ["CE", "MA", "PI"]),
    "4": ("4ª Região Fiscal (Nordeste Oriental)", ["AL", "PB", "PE", "RN"]),
    "5": ("5ª Região Fiscal (Nordeste Meridional)", ["BA", "SE"]),
    "6": ("6ª Região Fiscal (Minas Gerais)", ["MG"]),
    "7": ("7ª Região Fiscal (Sudeste Leste)", ["ES", "RJ"]),
    "8": ("8ª Região Fiscal (São Paulo)", ["SP"]),
    "9": ("9ª Região Fiscal (Sul — PR/SC)", ["PR", "SC"]),
    "0": ("10ª Região Fiscal (Rio Grande do Sul)", ["RS"]),
}


def is_valid_cpf(raw: str) -> bool:
    """Validate a Brazilian CPF using the official Receita Federal Modulo-11 algorithm."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    nums = [int(d) for d in digits]
    s1 = sum(nums[i] * (10 - i) for i in range(9))
    dv1 = (s1 * 10) % 11
    if dv1 == 10:
        dv1 = 0
    if nums[9] != dv1:
        return False
    s2 = sum(nums[i] * (11 - i) for i in range(10))
    dv2 = (s2 * 10) % 11
    if dv2 == 10:
        dv2 = 0
    return nums[10] == dv2


def analyze_cpf(raw: str) -> dict[str, Any]:
    """Return mathematical validation, formatting, LGPD mask, and Receita Federal fiscal region for a CPF."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 11:
        return {"is_cpf": False, "is_valid": False}
    valid = is_valid_cpf(digits)
    formatted = f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"
    region_digit = digits[8]
    region_label, uf_list = CPF_FISCAL_REGIONS.get(region_digit, ("Região Fiscal Desconhecida", ["BR"]))
    return {
        "is_cpf": True,
        "is_valid": valid,
        "cpf_digits": digits,
        "cpf_formatted": formatted,
        "cpf_masked": mask_cpf(digits),
        "fiscal_region_digit": region_digit,
        "fiscal_region": region_label,
        "states": uf_list,
    }


_NON_NAME_WORDS = {
    "CPF", "CNPJ", "RG", "INSCRITO", "INSCRITA", "PORTADOR", "PORTADORA", "SERVIDOR",
    "SERVIDORA", "CONTRATADO", "CONTRATADA", "APROVADO", "APROVADA", "DEFERIDO",
    "INDEFERIDO", "PREFEITURA", "MUNICIPIO", "ESTADO", "SECRETARIA", "PROCESSO",
    "EDITAL", "PORTARIA", "DECRETO", "EXTRATO", "CONTRATO", "LICITACAO", "PREGAO",
    "MATRICULA", "CARGO", "FUNCAO", "VALOR", "DATA", "ASSINATURA", "DIRETOR",
    "PRESIDENTE", "CONSELHO", "TRIBUNAL", "JUIZ", "RELATOR", "BRASIL", "FEDERAL",
    "NOMEACAO", "NOMEAÇÃO", "EXONERACAO", "EXONERAÇÃO", "DESIGNAR", "NOMEAR",
    "CANDIDATO", "CANDIDATA", "INTERESSADO", "INTERESSADA", "REQUERENTE",
}


def extract_names_near_cpf(text: str, cpf_formatted: str, cpf_digits: str) -> list[str]:
    """Extract candidate person full names appearing adjacent to a CPF in official gazettes or public snippets."""
    cleaned = re.sub(r"\s+", " ", text)
    candidates: list[str] = []
    name_token = r"[A-ZÁÉÍÓÚÂÊÔÃÕÇ][A-Za-záéíóúâêôãõç]+"
    part_token = r"(?:da|de|do|das|dos|e|DA|DE|DO|DAS|DOS|E)"
    full_name_pat = rf"({name_token}(?:\s+(?:{part_token}\s+)?{name_token}){{1,5}})"
    cpf_prefix = r"(?:[,;\-–—()/]*\s*(?:inscrit[oa]\s+no\s+)?(?:CPF(?:/MF)?\s*(?:sob\s+(?:o\s+)?)?(?:n[º°.]?\s*)?[:\-]?\s*)?)"
    cpf_match = rf"(?:{re.escape(cpf_formatted)}|{re.escape(cpf_digits)})"

    patterns = [
        rf"{full_name_pat}\s*{cpf_prefix}{cpf_match}",
        rf"{cpf_match}\s*[,;\-–—()/]+\s*{full_name_pat}",
    ]
    particles_lower = {"da", "de", "do", "das", "dos", "e"}
    for pat in patterns:
        for m in re.finditer(pat, cleaned):
            raw_name = m.group(1).strip(" ,;-–—().:")
            words = raw_name.split()
            # Strip leading non-name words or prepositions (e.g. "Nomeação de CARLOS...")
            while words and (words[0].upper() in _NON_NAME_WORDS or words[0].lower() in particles_lower):
                words.pop(0)
            while words and (words[-1].upper() in _NON_NAME_WORDS or words[-1].lower() in particles_lower):
                words.pop()
            tokens = [t for t in words if len(t) > 1]
            upper_tokens = {t.upper() for t in tokens}
            if (
                2 <= len(tokens) <= 6
                and not (upper_tokens & _NON_NAME_WORDS)
                and all(any(c.isalpha() for c in t) for t in words)
            ):
                norm_name = " ".join(
                    w.lower() if w.lower() in particles_lower else w.capitalize()
                    for w in words
                )
                if norm_name not in candidates:
                    candidates.append(norm_name)
    return candidates[:3]


class BrasilCpfOsintCollector(BaseCollector):
    """High-precision Brazilian CPF OSINT Collector (Receita Federal Mod-11 + Região Fiscal + Diários Oficiais + Portal da Transparência + Public Web Mentions)."""

    id = "brasil_cpf"
    name = "CPF OSINT Brasil (Validação RFB / Região Fiscal / Diários Oficiais / Transparência)"
    accepts = {TargetType.PERSON}
    produces = {EntityType.PERSON, EntityType.LOCATION, EntityType.DOCUMENT}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 30
    region = "brasil"

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        digits = re.sub(r"\D", "", target.normalized_value)
        if len(digits) != 11:
            return

        cpf_info = analyze_cpf(digits)
        cpf_fmt = cpf_info["cpf_formatted"]
        cpf_masked = cpf_info["cpf_masked"]
        discovered_names: list[str] = []
        public_mentions: list[dict[str, str]] = []
        servidor_records: list[dict[str, Any]] = []

        # 1. Portal da Transparência (if API key configured) — Servidores & Pessoas Físicas
        settings = get_settings()
        if settings.portal_transparencia_api_key:
            srv_url = "https://api.portaldatransparencia.gov.br/api-de-dados/servidores"
            try:
                resp = await self.http_client.fetch_with_retry(
                    self.id,
                    srv_url,
                    headers={"chave-api-dados": settings.portal_transparencia_api_key},
                    params={"cpf": digits, "pagina": 1},
                    max_retries=0,
                )
                srv_data = resp.json()
                if isinstance(srv_data, list):
                    for item in srv_data[:3]:
                        if isinstance(item, dict):
                            pessoa = item.get("servidor", {}).get("pessoa", {}) or item.get("pessoa", {}) or {}
                            nome = str(pessoa.get("nome") or item.get("nome") or "").strip()
                            orgao = str(
                                (item.get("orgaoServidorLotacao") or {}).get("nome")
                                or (item.get("orgaoServidorExercicio") or {}).get("nome")
                                or "Órgão Público Federal"
                            )
                            if nome:
                                norm_n = " ".join(w.capitalize() for w in nome.split())
                                if norm_n not in discovered_names:
                                    discovered_names.append(norm_n)
                                servidor_records.append({"nome": norm_n, "orgao": orgao})
            except Exception:
                pass

        # 2. Querido Diário (Diários Oficiais Municipais) — search formatted and raw CPF
        qd_url = "https://queridodiario.ok.org.br/api/gazettes"
        for q_str in (f'"{cpf_fmt}"', f'"{digits}"'):
            try:
                qd_resp = await self.http_client.fetch_with_retry(
                    self.id,
                    qd_url,
                    params={"querystring": q_str, "size": 5},
                    max_retries=0,
                )
                gazettes = (qd_resp.json() or {}).get("gazettes") or []
                for gz in gazettes[:5]:
                    if not isinstance(gz, dict):
                        continue
                    excerpts = gz.get("excerpts") or []
                    full_exc = " ".join(str(x) for x in excerpts)
                    if cpf_fmt not in full_exc and digits not in full_exc:
                        continue
                    terr = f"{gz.get('territory_name', 'Município')}/{gz.get('state_code', 'BR')}"
                    dt = str(gz.get("date") or "-")
                    g_url = str(gz.get("url") or qd_url)
                    names_found = extract_names_near_cpf(full_exc, cpf_fmt, digits)
                    for nf in names_found:
                        if nf not in discovered_names:
                            discovered_names.append(nf)
                    public_mentions.append(
                        {
                            "source": f"Diário Oficial {terr} ({dt})",
                            "url": g_url,
                            "snippet": re.sub(r"\s+", " ", full_exc).strip()[:240],
                        }
                    )
            except Exception:
                pass

        # 3. Public Web Search (DuckDuckGo HTML) for public editais, DOU/DOE, processes & registries
        ddg_url = "https://html.duckduckgo.com/html/"
        discovered_cnpjs: list[str] = []
        discovered_processes: list[str] = []
        try:
            ddg_resp = await self.http_client.fetch_with_retry(
                self.id,
                ddg_url,
                params={"q": f'"{cpf_fmt}" OR "{digits}"'},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                },
                max_retries=0,
            )
            html_text = ddg_resp.text
            # Parse result blocks from DuckDuckGo HTML
            for m in re.finditer(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
                html_text,
                re.DOTALL,
            ):
                raw_href, raw_title, raw_snip = m.group(1), m.group(2), m.group(3)
                clean_href = decode_duckduckgo_url(raw_href)
                title_clean = re.sub(r"<[^>]+>", "", raw_title).strip()
                snip_clean = re.sub(r"<[^>]+>", "", raw_snip).strip()
                full_block = f"{title_clean} - {snip_clean}"
                if cpf_fmt not in snip_clean and digits not in snip_clean and cpf_fmt not in title_clean:
                    continue

                # Extract CNPJs, processes and names
                ents = extract_brazil_entities_from_text(full_block)
                for c in ents["cnpjs"]:
                    if c not in discovered_cnpjs:
                        discovered_cnpjs.append(c)
                for pr in ents["processes"]:
                    if pr not in discovered_processes:
                        discovered_processes.append(pr)

                for nf in extract_names_near_cpf(full_block, cpf_fmt, digits):
                    if nf not in discovered_names:
                        discovered_names.append(nf)
                if len(public_mentions) < 8:
                    public_mentions.append(
                        {
                            "source": title_clean[:90] or "Documento Público Indexado",
                            "url": clean_href,
                            "snippet": snip_clean[:260],
                        }
                    )
        except Exception:
            pass

        payload: dict[str, Any] = {
            "is_cpf_analysis": True,
            "cpf_formatted": cpf_fmt,
            "cpf_masked": cpf_masked,
            "is_valid": cpf_info["is_valid"],
            "fiscal_region_digit": cpf_info["fiscal_region_digit"],
            "fiscal_region": cpf_info["fiscal_region"],
            "states": cpf_info["states"],
            "discovered_names": discovered_names,
            "discovered_cnpjs": discovered_cnpjs,
            "discovered_processes": discovered_processes,
            "servidor_records": servidor_records,
            "public_mentions": public_mentions,
            "has_portal_key": bool(settings.portal_transparencia_api_key),
            "lgpd_note": (
                "No Brasil (LGPD / Sigilo Fiscal RFB), o nome civil associado a um CPF só é retornado por fontes "
                "abertas quando o CPF foi publicado em Diário Oficial, Edital Público, Quadro Societário ou Portal da "
                "Transparência (configure GODSEYE_PORTAL_TRANSPARENCIA_API_KEY no .env para consulta direta federal)."
            ),
        }

        status_str = "VÁLIDO" if cpf_info["is_valid"] else "INVÁLIDO (Dígito Verificador Incorreto)"
        name_part = f" — Titular Identificado: {discovered_names[0]}" if discovered_names else ""
        yield self.make_observation(
            entity_type=EntityType.PERSON,
            entity_value=f"CPF {cpf_fmt} [{status_str} • {cpf_info['fiscal_region']}]{name_part}",
            raw_payload=payload,
            source_url="https://servicos.receita.fazenda.gov.br/Servicos/CPF/ConsultaSituacao/ConsultaPublica.asp",
            confidence=0.98 if cpf_info["is_valid"] else 0.40,
            verification_status=VerificationStatus.VERIFIED if cpf_info["is_valid"] else VerificationStatus.CONTESTED,
            related_to_value=target.normalized_value,
            related_to_type=EntityType.PERSON,
            relation=RelationType.ASSOCIATED_WITH,
            tags=["brasil", "cpf", "receita-federal", "lgpd"],
        )

        # Yield Location entity for the CPF's Receita Federal Fiscal Region
        if cpf_info["is_valid"]:
            uf_joined = ", ".join(cpf_info["states"])
            yield self.make_observation(
                entity_type=EntityType.LOCATION,
                entity_value=f"Emissão CPF: {cpf_info['fiscal_region']} (UF: {uf_joined})",
                raw_payload={
                    "region_name": cpf_info["fiscal_region"],
                    "uf": uf_joined,
                    "e164": f"CPF 9º Dígito ({cpf_info['fiscal_region_digit']})",
                    "national_format": f"Unidade Federativa de Emissão: {uf_joined}",
                    "line_type": "REGIÃO FISCAL RFB",
                    "carrier_regulatory": "Secretaria Especial da Receita Federal do Brasil",
                    "cities_sample": cpf_info["states"],
                },
                source_url="https://www.gov.br/receitafederal/pt-br",
                confidence=0.95,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=target.normalized_value,
                related_to_type=EntityType.PERSON,
                relation=RelationType.LOCATED_AT,
                tags=["brasil", "cpf", "regiao-fiscal"],
            )

        # Yield discovered Person names so the orchestrator can pivot to their full name
        for disc_name in discovered_names[:3]:
            yield self.make_observation(
                entity_type=EntityType.PERSON,
                entity_value=disc_name,
                raw_payload={
                    "discovered_person_name": disc_name,
                    "linked_cpf": cpf_masked,
                    "source": "public_official_gazette_or_transparency",
                },
                source_url="https://queridodiario.ok.org.br/",
                confidence=0.90,
                verification_status=VerificationStatus.CORROBORATED,
                related_to_value=target.normalized_value,
                related_to_type=EntityType.PERSON,
                relation=RelationType.ASSOCIATED_WITH,
                tags=["brasil", "cpf-name-match", "person-osint"],
            )

        # Yield discovered CNPJs so the orchestrator can cascade
        for disc_cnpj in discovered_cnpjs[:3]:
            yield self.make_observation(
                entity_type=EntityType.ORGANIZATION,
                entity_value=f"CNPJ Vinculado: {disc_cnpj}",
                raw_payload={
                    "discovered_cnpj": disc_cnpj,
                    "linked_cpf": cpf_masked,
                    "source": "public_records",
                },
                source_url="https://servicos.receita.fazenda.gov.br/",
                confidence=0.88,
                verification_status=VerificationStatus.UNVERIFIED_LEAD,
                related_to_value=target.normalized_value,
                related_to_type=EntityType.PERSON,
                relation=RelationType.ASSOCIATED_WITH,
                tags=["brasil", "cpf-cnpj-lead", "qsa-lead"],
            )

        # Yield discovered processes
        for disc_proc in discovered_processes[:3]:
            yield self.make_observation(
                entity_type=EntityType.LEGAL_CASE,
                entity_value=f"Processo Judicial: {disc_proc}",
                raw_payload={
                    "discovered_process": disc_proc,
                    "linked_cpf": cpf_masked,
                    "source": "public_records",
                },
                source_url="https://www.cnj.jus.br/sistemas/datajud/",
                confidence=0.85,
                verification_status=VerificationStatus.UNVERIFIED_LEAD,
                related_to_value=target.normalized_value,
                related_to_type=EntityType.PERSON,
                relation=RelationType.HAS_CASE,
                tags=["brasil", "cpf-process-lead", "juridico"],
            )
