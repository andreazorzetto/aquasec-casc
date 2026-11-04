"""Saved profiles: the same encrypted store the library's other tools use.

Thin wrappers, so the CLI never imports aquasec-lib directly. Nothing here
returns a secret: profile information carries a short hash of the key or user
name (``credentials_ref``) so two profiles can be told apart without exposing
either.
"""

from __future__ import annotations

import os


def _manager():
    from aquasec.config import ConfigManager
    return ConfigManager()


def setup(name: str | None = None) -> bool:
    """The library's interactive wizard: prompts, tests the connection, saves.

    With no name, the wizard asks for one (default: ``default``). Its calls carry
    the password and the token, so they verify TLS as every other command does:
    left to itself the library would not.
    """
    from aquasec.common import set_request_defaults
    from aquasec.config import interactive_setup

    from .settings import _timeout_from_env, _tls_from_env
    set_request_defaults(verify=_tls_from_env(os.environ), timeout=_timeout_from_env(os.environ),
                         allow_redirects=False)
    return bool(interactive_setup(name))


def default_name() -> str:
    return _manager().get_default_profile()


def all_info() -> list[dict]:
    from aquasec.config import get_all_profiles_info
    return get_all_profiles_info()


def info(name: str | None = None) -> dict | None:
    """One profile's information, or None. No name: the default profile."""
    from aquasec.config import get_profile_info
    return get_profile_info(name or default_name())


def delete(name: str) -> dict:
    """``{"success": bool, "error": str | None, ...}``"""
    from aquasec.config import delete_profile_with_result
    return delete_profile_with_result(name)


def set_default(name: str) -> dict:
    """``{"success": bool, "error": str | None, ...}``"""
    from aquasec.config import set_default_profile_with_result
    return set_default_profile_with_result(name)
