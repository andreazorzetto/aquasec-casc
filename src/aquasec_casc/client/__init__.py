"""The aquasec-lib adapter.

The only package that imports aquasec-lib. The reconciler sees it purely as an
``AquaClient``; see ``aquasec_casc.reconcile.client``.
"""

from .aquasec_client import AquasecClient, connect, sign_in, supported_kinds
from .settings import (
    ONPREM,
    SAAS_KEY,
    SAAS_USER,
    ConfigError,
    Credentials,
    Settings,
    env_has_credentials,
    resolve_settings,
    settings_from_env,
    settings_from_profile,
)

__all__ = [
    "AquasecClient",
    "ConfigError",
    "Credentials",
    "ONPREM",
    "SAAS_KEY",
    "SAAS_USER",
    "Settings",
    "connect",
    "env_has_credentials",
    "resolve_settings",
    "settings_from_env",
    "settings_from_profile",
    "sign_in",
    "supported_kinds",
]
