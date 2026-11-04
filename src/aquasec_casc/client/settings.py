"""Connection settings: where Aqua is, how to sign in, how to trust it.

Two sources, tried in this order unless ``--profile`` names one
(``resolve_settings``):

* **Environment variables**, the only source in Argo CD and CI. The names are
  this tool's own (``AQUA_URL``, ``AQUA_API_KEY`` ...), mapped onto the library
  here, so the library's historical variable names never matter.
* **A saved profile** from aquasec-lib (``~/.aqua``), for running from a laptop.
  The same encrypted profiles the library's other tools use. Credentials are
  read through ``ConfigManager`` directly rather than ``load_profile_credentials``,
  which would copy them into the process environment where any child process
  inherits them. With no ``--profile`` and no credentials in the environment,
  the default profile is used -- the same default the library's tools use.

TLS and timeout always come from the environment, whichever source supplied the
credentials.

TLS verification is ON by default here, unlike the library (which keeps it off
for backward compatibility). SaaS presents a public certificate, so this just
works; an on-prem console behind an internal CA needs ``AQUA_CA_BUNDLE``.
``AQUA_TLS_INSECURE=true`` exists as a deliberate, visible escape hatch.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Union

DEFAULT_METHODS = "ANY:*"
DEFAULT_TIMEOUT = 30.0

SAAS_KEY = "saas-key"
SAAS_USER = "saas-user"
ONPREM = "onprem"


class ConfigError(Exception):
    """The connection settings are missing, contradictory or invalid."""


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().strip('"').strip("'")
    return value or None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Credentials:
    """How to sign in. Never printed in full -- see __repr__."""

    mode: str
    console_url: str | None = None
    api_endpoint: str | None = None
    api_key: str | None = field(default=None, repr=False)
    api_secret: str | None = field(default=None, repr=False)
    role: str | None = None
    methods: str = DEFAULT_METHODS
    user: str | None = None
    password: str | None = field(default=None, repr=False)

    def describe(self) -> str:
        """A safe one-line description for logs: no key, secret or password."""
        if self.mode == SAAS_KEY:
            return f"SaaS API key via {self.api_endpoint} (role {self.role})"
        if self.mode == SAAS_USER:
            return f"SaaS user {self.user} via {self.api_endpoint}"
        return f"on-prem user {self.user} at {self.console_url}"


Verify = Union[bool, str]


@dataclass(frozen=True)
class Settings:
    credentials: Credentials
    verify: Verify = True
    timeout: float = DEFAULT_TIMEOUT
    source: str = "environment"


# --------------------------------------------------------------------------- #

def _tls_from_env(env: Mapping[str, str]) -> Verify:
    bundle = _clean(env.get("AQUA_CA_BUNDLE"))
    insecure = _truthy(env.get("AQUA_TLS_INSECURE"))

    if bundle and insecure:
        raise ConfigError(
            "AQUA_CA_BUNDLE and AQUA_TLS_INSECURE are both set. Choose one: a CA "
            "bundle to verify the console's certificate, or insecure to skip "
            "verification entirely."
        )
    if insecure:
        return False
    if bundle:
        if not os.path.isfile(bundle):
            raise ConfigError(f"AQUA_CA_BUNDLE points at {bundle!r}, which is not a file.")
        return bundle
    return True


def _timeout_from_env(env: Mapping[str, str]) -> float:
    raw = _clean(env.get("AQUA_TIMEOUT"))
    if raw is None:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"AQUA_TIMEOUT must be a number of seconds, got {raw!r}.")
    if value <= 0:
        raise ConfigError(f"AQUA_TIMEOUT must be positive, got {raw!r}.")
    return value


def _normalise_url(url: str | None) -> str | None:
    if not url:
        return None
    from aquasec.common import normalize_console_url
    return normalize_console_url(url) or None


_HELP = """Set one of these:

  SaaS, API key:        AQUA_API_KEY, AQUA_API_SECRET, AQUA_API_ENDPOINT, AQUA_ROLE
                        (AQUA_METHODS defaults to ANY:*; AQUA_URL is optional)
  SaaS, user/password:  AQUA_USER, AQUA_PASSWORD, AQUA_API_ENDPOINT
  On-prem:              AQUA_USER, AQUA_PASSWORD, AQUA_URL

or save a profile with 'aquasec-casc setup'. With no AQUA_* credentials set,
the default profile is used; --profile picks another."""


_CREDENTIAL_VARS = ("AQUA_API_KEY", "AQUA_API_SECRET", "AQUA_USER", "AQUA_PASSWORD")


def env_has_credentials(env: Mapping[str, str]) -> bool:
    """Any credential variable set -- even a partial set, which is then an error
    rather than a silent fall-through to a saved profile."""
    return any(_clean(env.get(name)) for name in _CREDENTIAL_VARS)


def credentials_from_env(env: Mapping[str, str]) -> Credentials:
    url = _normalise_url(_clean(env.get("AQUA_URL")))
    api_endpoint = _clean(env.get("AQUA_API_ENDPOINT"))
    key, secret = _clean(env.get("AQUA_API_KEY")), _clean(env.get("AQUA_API_SECRET"))
    user, password = _clean(env.get("AQUA_USER")), _clean(env.get("AQUA_PASSWORD"))

    has_key = bool(key or secret)
    has_user = bool(user or password)

    if has_key and has_user:
        raise ConfigError(
            "Both an API key (AQUA_API_KEY/AQUA_API_SECRET) and a user "
            "(AQUA_USER/AQUA_PASSWORD) are set. Set one, so it is unambiguous "
            "which identity the tool acts as."
        )

    if has_key:
        missing = [n for n, v in (("AQUA_API_KEY", key), ("AQUA_API_SECRET", secret),
                                  ("AQUA_API_ENDPOINT", api_endpoint),
                                  ("AQUA_ROLE", _clean(env.get("AQUA_ROLE")))) if not v]
        if missing:
            raise ConfigError(
                f"SaaS API-key sign-in needs {', '.join(missing)}. AQUA_API_ENDPOINT "
                "is the regional API host, e.g. https://eu-1.api.cloudsploit.com."
            )
        return Credentials(
            mode=SAAS_KEY, console_url=url, api_endpoint=api_endpoint.rstrip("/"),
            api_key=key, api_secret=secret, role=_clean(env.get("AQUA_ROLE")),
            methods=_clean(env.get("AQUA_METHODS")) or DEFAULT_METHODS,
        )

    if has_user:
        if not (user and password):
            raise ConfigError("User sign-in needs both AQUA_USER and AQUA_PASSWORD.")
        if api_endpoint:
            return Credentials(mode=SAAS_USER, console_url=url,
                               api_endpoint=api_endpoint.rstrip("/"),
                               user=user, password=password)
        if url:
            return Credentials(mode=ONPREM, console_url=url, user=user, password=password)
        raise ConfigError(
            "User sign-in needs either AQUA_URL (on-prem: the console URL) or "
            "AQUA_API_ENDPOINT (SaaS: the regional API host)."
        )

    raise ConfigError("No Aqua credentials found.\n\n" + _HELP)


def _https_only(credentials: Credentials, verify: Verify) -> Credentials:
    """A password over plain HTTP is readable by anything in between. It takes the
    same deliberate switch as skipping certificate checks."""
    for url in (credentials.console_url, credentials.api_endpoint):
        if url and not url.lower().startswith("https://") and verify is not False:
            raise ConfigError(
                f"{url} is not HTTPS, and credentials would cross the network in the clear. "
                "Use its https:// address. (AQUA_TLS_INSECURE=true allows it: not recommended.)")
    return credentials


def settings_from_env(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    verify = _tls_from_env(env)
    return Settings(
        credentials=_https_only(credentials_from_env(env), verify),
        verify=verify,
        timeout=_timeout_from_env(env),
        source="environment",
    )


def credentials_from_profile(name: str | None = None, config_manager=None) -> Credentials:
    """Credentials from an aquasec-lib profile, without touching the environment."""
    if config_manager is None:
        from aquasec.config import ConfigManager
        config_manager = ConfigManager()

    profile = name or config_manager.get_default_profile()
    if not profile or profile not in config_manager.list_profiles():
        available = ", ".join(sorted(config_manager.list_profiles())) or "none"
        raise ConfigError(f"No saved profile {profile!r}. Available: {available}.")

    config = config_manager.load_config(profile) or {}
    creds = config_manager.decrypt_credentials(profile) or {}
    if not creds:
        raise ConfigError(f"Profile {profile!r} has no readable credentials.")

    url = _normalise_url(config.get("csp_endpoint"))
    api_endpoint = (config.get("api_endpoint") or "").rstrip("/") or None

    if config.get("auth_method") == "api_keys":
        return Credentials(
            mode=SAAS_KEY, console_url=url, api_endpoint=api_endpoint,
            api_key=creds.get("api_key"), api_secret=creds.get("api_secret"),
            role=config.get("api_role"),
            methods=config.get("api_methods") or DEFAULT_METHODS,
        )
    if api_endpoint:
        return Credentials(mode=SAAS_USER, console_url=url, api_endpoint=api_endpoint,
                           user=creds.get("username"), password=creds.get("password"))
    if url:
        return Credentials(mode=ONPREM, console_url=url,
                           user=creds.get("username"), password=creds.get("password"))
    raise ConfigError(f"Profile {profile!r} has neither an API endpoint nor a console URL.")


def settings_from_profile(name: str | None = None, env: Mapping[str, str] | None = None,
                          config_manager=None) -> Settings:
    env = os.environ if env is None else env
    if config_manager is None:
        from aquasec.config import ConfigManager
        config_manager = ConfigManager()
    if not name:
        name = config_manager.get_default_profile()
    verify = _tls_from_env(env)
    return Settings(
        credentials=_https_only(credentials_from_profile(name, config_manager), verify),
        verify=verify,
        timeout=_timeout_from_env(env),
        source=f"profile '{name}'",
    )


def resolve_settings(profile: str | None = None, env: Mapping[str, str] | None = None,
                     config_manager=None) -> Settings:
    """Where the credentials come from: ``--profile``, then ``AQUA_*`` variables,
    then the default saved profile.

    The environment wins over the default profile so that a CI job or an Argo CD
    hook -- which set variables and have no profiles -- behave the same on a
    machine that happens to have one.
    """
    env = os.environ if env is None else env
    if profile:
        return settings_from_profile(profile, env, config_manager)
    if env_has_credentials(env):
        return settings_from_env(env)
    if config_manager is None:
        from aquasec.config import ConfigManager
        config_manager = ConfigManager()
    if config_manager.list_profiles():
        return settings_from_profile(None, env, config_manager)
    raise ConfigError("No Aqua credentials found.\n\n" + _HELP)
