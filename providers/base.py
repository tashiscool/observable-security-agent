"""Cloud provider adapter — normalize native evidence into canonical assessment models."""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import (
    AlertRule,
    AssessmentBundle,
    Asset,
    LogSource,
    PoamItem,
    ScannerFinding,
    ScannerTarget,
    SecurityEvent,
    Ticket,
)


class CloudProviderAdapter(ABC):
    """Abstract adapter from a cloud/account evidence source to canonical models."""

    @abstractmethod
    def load_bundle(self) -> AssessmentBundle:
        """Return the full normalized assessment input set."""

    @abstractmethod
    def list_assets(self) -> list[Asset]:
        """Discovered / live cloud assets."""

    @abstractmethod
    def list_events(self) -> list[SecurityEvent]:
        """Normalized security-relevant events (including control-plane and semantic records)."""

    @abstractmethod
    def list_scanner_targets(self) -> list[ScannerTarget]:
        """Scanner scope / target exports."""

    @abstractmethod
    def list_scanner_findings(self) -> list[ScannerFinding]:
        """Vulnerability and posture findings."""

    @abstractmethod
    def list_log_sources(self) -> list[LogSource]:
        """Central and local log routing evidence."""

    @abstractmethod
    def list_alert_rules(self) -> list[AlertRule]:
        """SIEM / platform alert definitions."""

    @abstractmethod
    def list_tickets(self) -> list[Ticket]:
        """Change and vulnerability tickets."""

    @abstractmethod
    def list_poam_items(self) -> list[PoamItem]:
        """Existing POA&M rows (seed inventory), if any."""

    @abstractmethod
    def provider_name(self) -> str:
        """Short provider identifier (e.g. ``fixture``, ``aws``)."""
