"""Collector Registry managing the 100+ OSINT source catalog and active adapters."""

from godseye.collectors.base import BaseCollector
from godseye.collectors.brazil_sources import (
    BrasilApiCnpjCollector,
    BrasilCepCollector,
    DataJudCnjCollector,
    PortalTransparenciaSanctionsCollector,
    QueridoDiarioCollector,
)
from godseye.collectors.catalog import build_full_catalog
from godseye.collectors.global_sources import (
    CrtShCollector,
    DnsDohCollector,
    GitHubOsintCollector,
    GravatarCollector,
    HibpMetadataCollector,
    IpApiGeoCollector,
    KeybaseCollector,
    RdapDomainCollector,
    RipeStatCollector,
    ShodanInternetDbCollector,
    UrlscanCollector,
    WaybackCollector,
)
from godseye.core.cache import MultiTierCache
from godseye.core.resilience import ResilientHttpClient
from godseye.domain.enums import TargetType
from godseye.domain.models import SourceMetadata


class CollectorRegistry:
    """Central catalog and registry of OSINT sources and live adapters (Section 4)."""

    def __init__(
        self,
        http_client: ResilientHttpClient,
        cache: MultiTierCache | None = None,
        offline_fallback: bool = True,
    ) -> None:
        self.http_client = http_client
        self.cache = cache
        self.offline_fallback = offline_fallback
        self._adapters: dict[str, BaseCollector] = {}
        self._register_default_adapters()
        self._catalog: dict[str, SourceMetadata] = {
            item.id: item for item in build_full_catalog(set(self._adapters.keys()))
        }

    def _register_default_adapters(self) -> None:
        adapter_classes: list[type[BaseCollector]] = [
            RdapDomainCollector,
            DnsDohCollector,
            CrtShCollector,
            ShodanInternetDbCollector,
            IpApiGeoCollector,
            RipeStatCollector,
            WaybackCollector,
            GitHubOsintCollector,
            GravatarCollector,
            KeybaseCollector,
            HibpMetadataCollector,
            UrlscanCollector,
            BrasilApiCnpjCollector,
            BrasilCepCollector,
            QueridoDiarioCollector,
            PortalTransparenciaSanctionsCollector,
            DataJudCnjCollector,
        ]
        for cls in adapter_classes:
            instance = cls(
                http_client=self.http_client,
                cache=self.cache,
                offline_fallback=self.offline_fallback,
            )
            self._adapters[instance.id] = instance

    def get_adapter(self, source_id: str) -> BaseCollector | None:
        """Retrieve a live collector adapter by its source ID."""
        source_meta = self._catalog.get(source_id)
        if source_meta and not source_meta.enabled:
            return None
        return self._adapters.get(source_id)

    def get_adapters_for_target(self, target_type: TargetType) -> list[BaseCollector]:
        """Return all enabled live adapters that accept the given TargetType."""
        matching: list[BaseCollector] = []
        for src_id, adapter in self._adapters.items():
            meta = self._catalog.get(src_id)
            if (meta is None or meta.enabled) and target_type in adapter.accepts:
                matching.append(adapter)
        return matching

    def list_sources(
        self,
        region: str | None = None,
        category: str | None = None,
        live_only: bool = False,
    ) -> list[SourceMetadata]:
        """List cataloged OSINT sources with optional filtering."""
        items = list(self._catalog.values())
        if region:
            items = [s for s in items if s.region.lower() == region.lower()]
        if category:
            items = [s for s in items if category.lower() in s.category.lower()]
        if live_only:
            items = [s for s in items if s.has_live_adapter]
        return items

    def get_source_metadata(self, source_id: str) -> SourceMetadata | None:
        """Get metadata for a specific source ID."""
        return self._catalog.get(source_id)

    def set_source_enabled(self, source_id: str, enabled: bool) -> SourceMetadata | None:
        """Enable or disable a source in the registry."""
        meta = self._catalog.get(source_id)
        if meta is not None:
            meta.enabled = enabled
        return meta
