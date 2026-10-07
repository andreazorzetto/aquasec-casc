"""The AquaClient implementation, on top of aquasec-lib.

This is the one module that knows aquasec-lib exists. The reconciler talks to
the four verbs of ``reconcile.client.AquaClient``; everything about signing in,
SaaS versus on-prem, TLS trust and translating library errors happens here.
If the tool is ever rewritten in Go, this file is the port surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

import requests
from aquasec import runtime_policies as rp
from aquasec.auth import api_auth, get_console_urls_from_token, user_pass_onprem_auth, user_pass_saas_auth
from aquasec.common import set_request_defaults, set_token_provider
from aquasec.exceptions import AquaError

from ..reconcile.client import ClientError
from ..schema.registry import KindDef
from .settings import ONPREM, SAAS_KEY, SAAS_USER, ConfigError, Credentials, Settings


# --------------------------------------------------------------------------- #
# Error translation
# --------------------------------------------------------------------------- #

def _translate(exc: Exception, action: str) -> ClientError:
    """Library and transport failures as ClientError, with an actionable message.

    Messages carry no credentials: library errors are built from server
    responses, and nothing here interpolates a key, secret or password.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return ClientError(
            f"{action}: the console's TLS certificate could not be verified. If it "
            "is issued by an internal CA, point AQUA_CA_BUNDLE at that CA's "
            "certificate. (AQUA_TLS_INSECURE=true skips verification, which is "
            "not recommended.)"
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return ClientError(f"{action}: Aqua did not respond in time. Raise AQUA_TIMEOUT if the "
                           "console is slow, or check connectivity.")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return ClientError(f"{action}: could not connect to Aqua. Check AQUA_URL / "
                           "AQUA_API_ENDPOINT and network access from where this runs.")
    if isinstance(exc, AquaError):
        return ClientError(f"{action}: {exc}", status=exc.status_code)
    return ClientError(f"{action}: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# Sign-in
# --------------------------------------------------------------------------- #

def sign_in(credentials: Credentials) -> str:
    """Obtain a bearer token. Raises ClientError on failure."""
    try:
        if credentials.mode == SAAS_KEY:
            return api_auth(credentials.api_key, credentials.api_secret,
                            credentials.api_endpoint, credentials.role,
                            json.dumps(credentials.methods.split(",")))
        if credentials.mode == SAAS_USER:
            return user_pass_saas_auth(credentials.user, credentials.password,
                                       credentials.api_endpoint)
        if credentials.mode == ONPREM:
            return user_pass_onprem_auth(credentials.user, credentials.password,
                                         credentials.console_url)
    except Exception as exc:  # noqa: BLE001 -- every failure becomes a ClientError
        raise _translate(exc, f"Sign-in failed ({credentials.describe()})") from None
    raise ConfigError(f"unknown sign-in mode {credentials.mode!r}")


def _console_url(credentials: Credentials, token: str) -> str:
    """The console's REST URL: configured, or read from the SaaS token itself.

    Read from the token directly rather than via the library's
    resolve_console_url(), which would let a stray CSP_ENDPOINT in the
    environment override what this tool was configured with.
    """
    if credentials.console_url:
        return credentials.console_url
    url = (get_console_urls_from_token(token) or {}).get("console")
    if not url:
        raise ConfigError("Could not work out the console URL from the token; set AQUA_URL.")
    return url


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Ops:
    get: Callable[..., Any]
    create: Callable[..., Any]
    update: Callable[..., Any]
    delete: Callable[..., Any]


def _runtime_policy_ops() -> _Ops:
    return _Ops(
        get=lambda c, name: rp.get_runtime_policy(c.server, c.token, name, timeout=c.timeout),
        create=lambda c, body: rp.create_runtime_policy(c.server, c.token, body, timeout=c.timeout),
        update=lambda c, name, body: rp.update_runtime_policy(c.server, c.token, name, body,
                                                              timeout=c.timeout),
        delete=lambda c, name: rp.delete_runtime_policy(c.server, c.token, name,
                                                        missing_ok=True, timeout=c.timeout),
    )


#: Kinds this client can serve. A kind in the schema registry but not here is a
#: build error, reported clearly rather than as an AttributeError mid-run.
_OPERATIONS: dict[str, Callable[[], _Ops]] = {
    "RuntimePolicy": _runtime_policy_ops,
}


def supported_kinds() -> list[str]:
    return sorted(_OPERATIONS)


class AquasecClient:
    """AquaClient on top of aquasec-lib. Build it with ``connect()``."""

    def __init__(self, server: str, token: str, timeout: float) -> None:
        self.server = server
        self.token = token
        self.timeout = timeout

    def _ops(self, kind: KindDef) -> _Ops:
        factory = _OPERATIONS.get(kind.kind)
        if factory is None:
            raise ClientError(
                f"{kind.kind} is not supported by this client yet "
                f"(supported: {', '.join(supported_kinds())})"
            )
        return factory()

    def get(self, kind: KindDef, name: str) -> dict | None:
        try:
            return self._ops(kind).get(self, name)
        except ClientError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc, f"Reading {kind.kind} {name!r}") from None

    def create(self, kind: KindDef, body: dict) -> dict:
        name = body.get("name")
        try:
            created = self._ops(kind).create(self, body)
        except ClientError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc, f"Creating {kind.kind} {name!r}") from None
        # Aqua returns the complete object on create (verified live). If a
        # version ever returns nothing, read it back so the caller still gets
        # the server's view, including its numeric id.
        return created if isinstance(created, dict) else (self.get(kind, name) or {})

    def update(self, kind: KindDef, name: str, body: dict) -> dict:
        try:
            updated = self._ops(kind).update(self, name, body)
        except ClientError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc, f"Updating {kind.kind} {name!r}") from None
        return updated if isinstance(updated, dict) else {}

    def delete(self, kind: KindDef, name: str) -> None:
        try:
            self._ops(kind).delete(self, name)
        except ClientError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc, f"Deleting {kind.kind} {name!r}") from None


def connect(settings: Settings) -> AquasecClient:
    """Configure the library, sign in, and return a ready client.

    Sets library-wide state (TLS, timeout, token refresh). That is fine for a
    run-once CLI process; a long-running operator would hold one client.
    """
    set_request_defaults(verify=settings.verify, timeout=settings.timeout)

    credentials = settings.credentials
    token = sign_in(credentials)

    # On a 401 mid-run (token expiry on a large tenant), sign in again with the
    # same credentials rather than failing the whole reconcile.
    set_token_provider(lambda: sign_in(credentials))

    return AquasecClient(_console_url(credentials, token), token, settings.timeout)
