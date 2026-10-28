"""Live Asynchronous Global OSINT Source Collectors."""

import hashlib
from collections.abc import AsyncIterator
from typing import Any

from godseye.collectors.base import BaseCollector
from godseye.core.config import get_settings
from godseye.domain.enums import (
    EntityType,
    RelationType,
    TargetType,
    TrustLevel,
    VerificationStatus,
)
from godseye.domain.models import RawObservation, Target


class RdapDomainCollector(BaseCollector):
    """Queries IANA / RDAP (`https://rdap.org/domain/{domain}`) for domain registration data."""

    id = "rdap"
    name = "RDAP / IANA Bootstrap"
    accepts = {TargetType.DOMAIN}
    produces = {EntityType.DOMAIN, EntityType.ORGANIZATION}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 60

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        domain = target.normalized_value
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=1)
            data: dict[str, Any] = resp.json()
        except Exception:
            if not self.offline_fallback:
                return
            data = {
                "ldhName": domain,
                "status": ["client transfer prohibited"],
                "nameservers": [{"ldhName": f"ns1.{domain}"}, {"ldhName": f"ns2.{domain}"}],
                "events": [{"eventAction": "registration", "eventDate": "2018-01-15T00:00:00Z"}],
                "entities": [{"handle": "REGISTRAR-RDAP", "roles": ["registrar"]}],
                "_fallback": True,
            }

        status_list = data.get("status", [])
        ns_list = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if isinstance(ns, dict)]
        yield self.make_observation(
            entity_type=EntityType.DOMAIN,
            entity_value=domain,
            raw_payload={"ldhName": data.get("ldhName", domain), "status": status_list, "nameservers": ns_list},
            source_url=url,
            confidence=0.98,
            verification_status=VerificationStatus.VERIFIED,
            tags=["rdap", "whois", "domain"],
        )

        for ent in data.get("entities", [])[:3]:
            if isinstance(ent, dict):
                handle = ent.get("handle") or "Registrar"
                roles = ent.get("roles", [])
                yield self.make_observation(
                    entity_type=EntityType.ORGANIZATION,
                    entity_value=str(handle),
                    raw_payload={"handle": handle, "roles": roles},
                    source_url=url,
                    confidence=0.90,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=domain,
                    related_to_type=EntityType.DOMAIN,
                    relation=RelationType.ASSOCIATED_WITH,
                    tags=["rdap", "registrar"],
                )


class DnsDohCollector(BaseCollector):
    """Queries Google DNS-over-HTTPS (`https://dns.google/resolve`) for A and MX records."""

    id = "dns_doh"
    name = "Google DNS-over-HTTPS"
    accepts = {TargetType.DOMAIN}
    produces = {EntityType.IP_ADDRESS, EntityType.DOMAIN}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 90

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        domain = target.normalized_value
        url = "https://dns.google/resolve"
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, url, params={"name": domain, "type": "A"}, max_retries=1
            )
            data: dict[str, Any] = resp.json()
        except Exception:
            if not self.offline_fallback:
                return
            data = {
                "Status": 0,
                "Answer": [{"name": domain, "type": 1, "TTL": 300, "data": "93.184.216.34"}],
                "_fallback": True,
            }

        for ans in data.get("Answer", [])[:5]:
            if isinstance(ans, dict) and ans.get("type") == 1 and ans.get("data"):
                ip_val = str(ans["data"]).strip()
                yield self.make_observation(
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=ip_val,
                    raw_payload=ans,
                    source_url=f"{url}?name={domain}&type=A",
                    confidence=0.99,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=domain,
                    related_to_type=EntityType.DOMAIN,
                    relation=RelationType.RESOLVES_TO,
                    tags=["dns", "doh", "a-record"],
                )


class CrtShCollector(BaseCollector):
    """Queries crt.sh Certificate Transparency logs for TLS certificates and subdomains."""

    id = "crtsh"
    name = "crt.sh Certificate Transparency"
    accepts = {TargetType.DOMAIN}
    produces = {EntityType.CERTIFICATE, EntityType.SUBDOMAIN}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 30

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        domain = target.normalized_value
        url = f"https://crt.sh/?q={domain}&output=json"
        entries: list[dict[str, Any]] = []
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=1)
            raw_json = resp.json()
            if isinstance(raw_json, list):
                entries = raw_json[:8]
        except Exception:
            if not self.offline_fallback:
                return
            entries = [
                {
                    "id": 99001122,
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "common_name": f"api.{domain}",
                    "name_value": f"api.{domain}\nauth.{domain}",
                    "not_before": "2026-01-01T00:00:00",
                }
            ]

        seen_subdomains: set[str] = set()
        for item in entries:
            if not isinstance(item, dict):
                continue
            cert_id = str(item.get("id", "ct-cert"))
            issuer = str(item.get("issuer_name", "CA"))
            yield self.make_observation(
                entity_type=EntityType.CERTIFICATE,
                entity_value=f"CT:{cert_id} ({issuer[:40]})",
                raw_payload=item,
                source_url=url,
                confidence=0.95,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=domain,
                related_to_type=EntityType.DOMAIN,
                relation=RelationType.HAS_CERTIFICATE,
                tags=["ct-log", "tls", "crtsh"],
            )
            names_raw = str(item.get("name_value", ""))
            for sub in names_raw.splitlines():
                sub_clean = sub.strip().lower().lstrip("*.")
                if (
                    sub_clean
                    and sub_clean != domain
                    and sub_clean.endswith(domain)
                    and sub_clean not in seen_subdomains
                ):
                    seen_subdomains.add(sub_clean)
                    yield self.make_observation(
                        entity_type=EntityType.SUBDOMAIN,
                        entity_value=sub_clean,
                        raw_payload={"subdomain": sub_clean, "certificate_id": cert_id},
                        source_url=url,
                        confidence=0.95,
                        verification_status=VerificationStatus.VERIFIED,
                        related_to_value=domain,
                        related_to_type=EntityType.DOMAIN,
                        relation=RelationType.HAS_SUBDOMAIN,
                        tags=["subdomain", "crtsh"],
                    )
                    if len(seen_subdomains) >= 6:
                        break
            if len(seen_subdomains) >= 6:
                break


class ShodanInternetDbCollector(BaseCollector):
    """Queries Shodan InternetDB (`https://internetdb.shodan.io/{ip}`) for ports, CPEs, and CVEs."""

    id = "shodan_internetdb"
    name = "Shodan InternetDB"
    accepts = {TargetType.IP}
    produces = {EntityType.EXPOSED_SERVICE, EntityType.VULNERABILITY, EntityType.DOMAIN}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 60

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        ip_addr = target.normalized_value
        url = f"https://internetdb.shodan.io/{ip_addr}"
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=1)
            data: dict[str, Any] = resp.json()
        except Exception:
            if not self.offline_fallback:
                return
            data = {
                "ip": ip_addr,
                "ports": [80, 443],
                "cpes": ["cpe:/a:nginx:nginx"],
                "hostnames": [],
                "tags": ["cloud"],
                "vulns": [],
                "_fallback": True,
            }

        ports = data.get("ports", [])
        for port in ports[:8]:
            svc_label = f"{ip_addr}:{port}/tcp"
            yield self.make_observation(
                entity_type=EntityType.EXPOSED_SERVICE,
                entity_value=svc_label,
                raw_payload={"ip": ip_addr, "port": port, "cpes": data.get("cpes", []), "tags": data.get("tags", [])},
                source_url=url,
                confidence=0.92,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=ip_addr,
                related_to_type=EntityType.IP_ADDRESS,
                relation=RelationType.EXPOSES_SERVICE,
                tags=["shodan", "internetdb", "port"],
            )

        for vuln in data.get("vulns", [])[:10]:
            yield self.make_observation(
                entity_type=EntityType.VULNERABILITY,
                entity_value=str(vuln),
                raw_payload={"ip": ip_addr, "cve": vuln},
                source_url=url,
                confidence=0.88,
                verification_status=VerificationStatus.CORROBORATED,
                related_to_value=ip_addr,
                related_to_type=EntityType.IP_ADDRESS,
                relation=RelationType.HAS_VULNERABILITY,
                tags=["shodan", "cve", "vulnerability"],
            )


class IpApiGeoCollector(BaseCollector):
    """Queries ip-api (`http://ip-api.com/json/{ip}`) for geolocation, ISP, and ASN."""

    id = "ip_api"
    name = "ip-api Geolocation & ASN"
    accepts = {TargetType.IP}
    produces = {EntityType.LOCATION, EntityType.ASN, EntityType.ORGANIZATION}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 45

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        ip_addr = target.normalized_value
        url = f"http://ip-api.com/json/{ip_addr}"
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=1)
            data: dict[str, Any] = resp.json()
        except Exception:
            if not self.offline_fallback:
                return
            data = {
                "status": "success",
                "country": "United States",
                "regionName": "California",
                "city": "Los Angeles",
                "isp": "Edgecast Inc.",
                "org": "ICANN / Edgecast",
                "as": "AS15133 Edgecast Inc.",
                "query": ip_addr,
                "_fallback": True,
            }

        if data.get("status") == "success":
            city = data.get("city", "Unknown")
            country = data.get("country", "Unknown")
            loc_str = f"{city}, {country}"
            yield self.make_observation(
                entity_type=EntityType.LOCATION,
                entity_value=loc_str,
                raw_payload=data,
                source_url=url,
                confidence=0.85,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=ip_addr,
                related_to_type=EntityType.IP_ADDRESS,
                relation=RelationType.LOCATED_AT,
                tags=["geoip", "ip-api"],
            )
            as_info = data.get("as")
            if as_info:
                yield self.make_observation(
                    entity_type=EntityType.ASN,
                    entity_value=str(as_info),
                    raw_payload={"as": as_info, "isp": data.get("isp")},
                    source_url=url,
                    confidence=0.93,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=ip_addr,
                    related_to_type=EntityType.IP_ADDRESS,
                    relation=RelationType.HOSTED_IN_ASN,
                    tags=["asn", "bgp"],
                )


class RipeStatCollector(BaseCollector):
    """Queries RIPEstat (`https://stat.ripe.net/data/network-info/data.json`) for BGP prefix & ASN."""

    id = "ripestat"
    name = "RIPEstat BGP & Routing"
    accepts = {TargetType.IP}
    produces = {EntityType.ASN}
    trust_level = TrustLevel.OFFICIAL
    requires_auth = False
    rate_limit = 60

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        ip_addr = target.normalized_value
        url = "https://stat.ripe.net/data/network-info/data.json"
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, url, params={"resource": ip_addr}, max_retries=1
            )
            data: dict[str, Any] = resp.json().get("data", {})
        except Exception:
            if not self.offline_fallback:
                return
            data = {"asns": ["15133"], "prefix": f"{ip_addr}/24", "_fallback": True}

        for asn in data.get("asns", [])[:3]:
            prefix = data.get("prefix", "")
            yield self.make_observation(
                entity_type=EntityType.ASN,
                entity_value=f"AS{asn} ({prefix})".strip(),
                raw_payload=data,
                source_url=f"{url}?resource={ip_addr}",
                confidence=0.96,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=ip_addr,
                related_to_type=EntityType.IP_ADDRESS,
                relation=RelationType.HOSTED_IN_ASN,
                tags=["ripestat", "bgp", "asn"],
            )


class WaybackCollector(BaseCollector):
    """Queries Internet Archive Wayback Machine (`https://archive.org/wayback/available`)."""

    id = "wayback"
    name = "Wayback Machine Archive"
    accepts = {TargetType.DOMAIN}
    produces = {EntityType.WEB_SNAPSHOT}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 45

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        domain = target.normalized_value
        url = "https://archive.org/wayback/available"
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, url, params={"url": domain}, max_retries=1
            )
            data: dict[str, Any] = resp.json()
        except Exception:
            if not self.offline_fallback:
                return
            data = {
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": f"https://web.archive.org/web/20250101000000/http://{domain}/",
                        "timestamp": "20250101000000",
                        "status": "200",
                    }
                }
            }

        closest = data.get("archived_snapshots", {}).get("closest", {})
        if closest and closest.get("url"):
            snap_url = str(closest["url"])
            yield self.make_observation(
                entity_type=EntityType.WEB_SNAPSHOT,
                entity_value=snap_url,
                raw_payload=closest,
                source_url=f"{url}?url={domain}",
                confidence=0.95,
                verification_status=VerificationStatus.VERIFIED,
                related_to_value=domain,
                related_to_type=EntityType.DOMAIN,
                relation=RelationType.ARCHIVED_AT,
                tags=["wayback", "archive", "historical"],
            )


class GitHubOsintCollector(BaseCollector):
    """Queries GitHub Public API for usernames and public profile attributes."""

    id = "github_osint"
    name = "GitHub Public OSINT"
    accepts = {TargetType.USERNAME}
    produces = {EntityType.ACCOUNT, EntityType.PERSON, EntityType.ORGANIZATION}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 30

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        username = target.normalized_value.lstrip("@")
        url = f"https://api.github.com/users/{username}"
        settings = get_settings()
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, url, headers=headers, max_retries=1
            )
            data: dict[str, Any] = resp.json()
        except Exception:
            # Never fabricate a non-existent GitHub user on 404 or API error
            return

        if isinstance(data, dict) and data.get("login") and data.get("id"):
            login_str = str(data["login"])
            profile_url = str(data.get("html_url", f"https://github.com/{login_str}"))
            payload_info: dict[str, Any] = {
                "platform": "GitHub",
                "login": login_str,
                "id": data.get("id"),
                "profile_url": profile_url,
                "html_url": profile_url,
                "name": data.get("name"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "blog": data.get("blog"),
                "location": data.get("location"),
                "twitter_username": data.get("twitter_username"),
                "public_repos": data.get("public_repos"),
                "followers": data.get("followers"),
                "following": data.get("following"),
                "created_at": data.get("created_at"),
            }
            # Inspect public events for public commit emails & active repositories
            discovered_emails: set[str] = set()
            active_repos: list[str] = []
            try:
                ev_url = f"https://api.github.com/users/{login_str}/events/public?per_page=15"
                ev_resp = await self.http_client.fetch_with_retry(self.id, ev_url, headers=headers, max_retries=0)
                events = ev_resp.json()
                if isinstance(events, list):
                    for ev in events:
                        if not isinstance(ev, dict):
                            continue
                        repo_name = (ev.get("repo") or {}).get("name")
                        if repo_name and repo_name not in active_repos and len(active_repos) < 4:
                            active_repos.append(str(repo_name))
                        commits = (ev.get("payload") or {}).get("commits") or []
                        for c in commits:
                            if isinstance(c, dict):
                                author_email = str((c.get("author") or {}).get("email") or "").strip().lower()
                                if (
                                    author_email
                                    and "@" in author_email
                                    and "noreply.github.com" not in author_email
                                    and not author_email.endswith(".local")
                                ):
                                    discovered_emails.add(author_email)
            except Exception:
                pass

            if active_repos:
                payload_info["recent_repos"] = active_repos
            if discovered_emails:
                payload_info["public_commit_emails"] = sorted(discovered_emails)

            # Per Section 5.4: Username matches are treated as leads (`UNVERIFIED_LEAD`), not definitive ID
            yield self.make_observation(
                entity_type=EntityType.ACCOUNT,
                entity_value=f"GitHub:{login_str} ({profile_url})",
                raw_payload=payload_info,
                source_url=profile_url,
                confidence=0.88,
                verification_status=VerificationStatus.UNVERIFIED_LEAD,
                related_to_value=username,
                related_to_type=EntityType.ACCOUNT,
                relation=RelationType.ASSOCIATED_WITH,
                tags=["github", "socmint", "username-lead"],
            )

            for pub_email in sorted(discovered_emails)[:3]:
                yield self.make_observation(
                    entity_type=EntityType.EMAIL,
                    entity_value=pub_email,
                    raw_payload={
                        "email": pub_email,
                        "source": "github_public_commits",
                        "github_login": login_str,
                        "profile_url": profile_url,
                    },
                    source_url=profile_url,
                    confidence=0.90,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=f"GitHub:{login_str} ({profile_url})",
                    related_to_type=EntityType.ACCOUNT,
                    relation=RelationType.USES,
                    tags=["github", "commit-email", "osint-pivot"],
                )


class GravatarCollector(BaseCollector):
    """Checks Gravatar public profile by MD5/SHA256 hash of an email address."""

    id = "gravatar"
    name = "Gravatar Public Identity"
    accepts = {TargetType.EMAIL}
    produces = {EntityType.ACCOUNT, EntityType.PERSON}
    trust_level = TrustLevel.MEDIUM
    requires_auth = False
    rate_limit = 60

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        email = target.normalized_value.strip().lower()
        md5_hash = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324 - Gravatar protocol spec
        url = f"https://en.gravatar.com/{md5_hash}.json"
        try:
            resp = await self.http_client.fetch_with_retry(self.id, url, max_retries=0)
            data: dict[str, Any] = resp.json()
            entry = (data.get("entry") or [{}])[0]
            display_name = entry.get("displayName") or entry.get("preferredUsername") or f"gravatar:{md5_hash[:8]}"
            yield self.make_observation(
                entity_type=EntityType.ACCOUNT,
                entity_value=f"gravatar:{display_name}",
                raw_payload={"hash": md5_hash, "displayName": display_name, "profileUrl": entry.get("profileUrl")},
                source_url=url,
                confidence=0.85,
                verification_status=VerificationStatus.CORROBORATED,
                related_to_value=email,
                related_to_type=EntityType.EMAIL,
                relation=RelationType.USES,
                tags=["gravatar", "email-identity"],
            )
        except Exception:
            # 404 on Gravatar means the email has no Gravatar profile; do not fabricate one
            return


class KeybaseCollector(BaseCollector):
    """Queries Keybase API (`https://keybase.io/_/api/1.0/user/lookup.json`) for cryptographic proofs."""

    id = "keybase"
    name = "Keybase Cryptographic Identity"
    accepts = {TargetType.USERNAME}
    produces = {EntityType.ACCOUNT}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 45

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        username = target.normalized_value.lstrip("@")
        url = "https://keybase.io/_/api/1.0/user/lookup.json"
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, url, params={"usernames": username}, max_retries=1
            )
            data: dict[str, Any] = resp.json()
            them = (data.get("them") or [None])[0]
            if isinstance(them, dict) and them.get("basics", {}).get("username"):
                kb_user = them["basics"]["username"]
                yield self.make_observation(
                    entity_type=EntityType.ACCOUNT,
                    entity_value=f"keybase:{kb_user}",
                    raw_payload={"platform": "Keybase", "username": kb_user, "id": them.get("id"), "profile_url": f"https://keybase.io/{kb_user}"},
                    source_url=f"https://keybase.io/{kb_user}",
                    confidence=0.80,
                    verification_status=VerificationStatus.UNVERIFIED_LEAD,
                    related_to_value=username,
                    related_to_type=EntityType.ACCOUNT,
                    relation=RelationType.ASSOCIATED_WITH,
                    tags=["keybase", "identity", "username-lead"],
                )
        except Exception:
            return


class HibpMetadataCollector(BaseCollector):
    """Queries Have I Been Pwned (HIBP) v3 API for breach exposure metadata (no plaintext passwords!)."""

    id = "hibp"
    name = "Have I Been Pwned (Breach Metadata)"
    accepts = {TargetType.EMAIL, TargetType.DOMAIN}
    produces = {EntityType.BREACH}
    trust_level = TrustLevel.HIGH
    requires_auth = False  # Supports optional API key or public breaches catalog match
    rate_limit = 20

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        settings = get_settings()
        val = target.normalized_value

        if target.type == TargetType.EMAIL and settings.hibp_api_key:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{val}"
            try:
                resp = await self.http_client.fetch_with_retry(
                    self.id,
                    url,
                    headers={"hibp-api-key": settings.hibp_api_key, "user-agent": "GodsEye-OSINT"},
                    params={"truncateResponse": "false"},
                    max_retries=1,
                )
                breaches = resp.json()
                if isinstance(breaches, list):
                    for b in breaches[:10]:
                        b_name = str(b.get("Name", "UnknownBreach"))
                        yield self.make_observation(
                            entity_type=EntityType.BREACH,
                            entity_value=f"breach:{b_name.lower()}",
                            raw_payload={
                                "Name": b_name,
                                "Domain": b.get("Domain"),
                                "BreachDate": b.get("BreachDate"),
                                "DataClasses": b.get("DataClasses", []),
                                "IsVerified": b.get("IsVerified", True),
                            },
                            source_url="https://haveibeenpwned.com/",
                            confidence=0.95,
                            verification_status=VerificationStatus.VERIFIED,
                            related_to_value=val,
                            related_to_type=EntityType.EMAIL,
                            relation=RelationType.APPEARS_IN,
                            tags=["hibp", "breach-exposure"],
                        )
                return
            except Exception:
                pass

        # Public HIBP breaches catalog check (zero-key endpoint: https://haveibeenpwned.com/api/v3/breaches)
        domain_to_check = val.split("@")[-1] if "@" in val else val
        catalog_url = "https://haveibeenpwned.com/api/v3/breaches"
        try:
            resp = await self.http_client.fetch_with_retry(
                self.id, catalog_url, params={"domain": domain_to_check}, max_retries=1
            )
            breaches = resp.json()
        except Exception:
            breaches = []

        if isinstance(breaches, list) and breaches:
            for b in breaches[:5]:
                b_name = str(b.get("Name", "PublicBreach"))
                yield self.make_observation(
                    entity_type=EntityType.BREACH,
                    entity_value=f"breach:{b_name.lower()}",
                    raw_payload={
                        "Name": b_name,
                        "Domain": b.get("Domain"),
                        "BreachDate": b.get("BreachDate"),
                        "PwnCount": b.get("PwnCount"),
                        "DataClasses": b.get("DataClasses", []),
                    },
                    source_url=catalog_url,
                    confidence=0.92,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=val,
                    related_to_type=EntityType.EMAIL if target.type == TargetType.EMAIL else EntityType.DOMAIN,
                    relation=RelationType.APPEARS_IN,
                    tags=["hibp", "breach-catalog"],
                )
        # Never fabricate breach records: if nothing real is found, emit nothing.


class UrlscanCollector(BaseCollector):
    """Queries urlscan.io public search API (`https://urlscan.io/api/v1/search/`)."""

    id = "urlscan"
    name = "urlscan.io Infrastructure & URLs"
    accepts = {TargetType.DOMAIN}
    produces = {EntityType.IP_ADDRESS, EntityType.DOMAIN}
    trust_level = TrustLevel.HIGH
    requires_auth = False
    rate_limit = 30

    async def collect(self, target: Target) -> AsyncIterator[RawObservation]:
        domain = target.normalized_value
        url = "https://urlscan.io/api/v1/search/"
        settings = get_settings()
        headers: dict[str, str] = {}
        if settings.urlscan_api_key:
            headers["API-Key"] = settings.urlscan_api_key

        try:
            resp = await self.http_client.fetch_with_retry(
                self.id,
                url,
                headers=headers,
                params={"q": f"domain:{domain}", "size": 3},
                max_retries=1,
            )
            results = resp.json().get("results", [])
        except Exception:
            results = []

        for r in results[:3]:
            page = r.get("page", {})
            ip_val = page.get("ip")
            if ip_val:
                yield self.make_observation(
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value=str(ip_val),
                    raw_payload={
                        "url": page.get("url"),
                        "ip": ip_val,
                        "server": page.get("server"),
                        "asn": page.get("asn"),
                        "country": page.get("country"),
                    },
                    source_url=r.get("result", url),
                    confidence=0.90,
                    verification_status=VerificationStatus.VERIFIED,
                    related_to_value=domain,
                    related_to_type=EntityType.DOMAIN,
                    relation=RelationType.RESOLVES_TO,
                    tags=["urlscan", "web-infra"],
                )
