"""Interoperability shims (OCSF-like export, etc.); canonical models remain in ``core``."""

from normalization.ocsf_export import security_event_to_ocsf_like_export

__all__ = ["security_event_to_ocsf_like_export"]
