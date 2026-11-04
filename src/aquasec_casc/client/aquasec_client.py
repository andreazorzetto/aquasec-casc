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
from aquasec import assurance_policies as ap
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
    # Not the text: a requests error can quote a header, and so a key.
    return ClientError(f"{action}: {type(exc).__name__}")


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
    if not url.lower().startswith("https://"):
        raise ConfigError(f"The token names a console that is not HTTPS: {url}. Set AQUA_URL.")
    return url


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Ops:
    list: Callable[..., Any]
    get: Callable[..., Any]
    create: Callable[..., Any]
    update: Callable[..., Any]
    delete: Callable[..., Any]


def _runtime_policy_ops() -> _Ops:
    return _Ops(
        # The list response carries name, description and is_ootb_policy for
        # every policy (verified), so orphan discovery is one paginated call.
        list=lambda c: rp.get_all_runtime_policies(c.server, c.token, timeout=c.timeout),
        get=lambda c, name: rp.get_runtime_policy(c.server, c.token, name, timeout=c.timeout),
        create=lambda c, body: rp.create_runtime_policy(c.server, c.token, body, timeout=c.timeout),
        update=lambda c, name, body: rp.update_runtime_policy(c.server, c.token, name, body,
                                                              timeout=c.timeout),
        delete=lambda c, name: rp.delete_runtime_policy(c.server, c.token, name,
                                                        missing_ok=True, timeout=c.timeout),
    )


def _kubernetes_read_view(policy: dict | None) -> dict | None:
    """A Kubernetes policy's checks, as the one list the schema has.

    Aqua keeps three: ``kubernetes_controls`` with an ``enabled`` flag on every
    check (always right), and names and AVD ids of the enabled ones (empty on a
    2022.4 export). So the names are read from the flags.
    """
    if not policy or policy.get("assurance_type") != "kubernetes":
        return policy
    enabled = [c["name"] for c in policy.get("kubernetes_controls") or [] if c.get("enabled")]
    return {**policy, "kubernetes_controls_names": sorted(enabled)}


def _kubernetes_write_view(body: dict) -> dict:
    """The reverse: all three lists saying the same.

    On update, Aqua goes by the AVD ids if there are any, then the names, then
    the flags (write-tested), and a create may have no flags to set. So the names
    and flags are what is wanted, and the ids are left for Aqua to work out.
    """
    if body.get("assurance_type") != "kubernetes" or body.get("kubernetes_controls_names") is None:
        return body
    names = body["kubernetes_controls_names"]
    out = {**body, "kubernetes_controls_avd_ids": []}
    if body.get("kubernetes_controls"):
        out["kubernetes_controls"] = [{**c, "enabled": c.get("name") in names}
                                      for c in body["kubernetes_controls"]]
    return out


def _all_assurance_policies(c) -> list[dict]:
    """Every type's, each carrying its type: names are unique only within one."""
    found = []
    for assurance_type in ap.ASSURANCE_TYPES:
        try:
            policies = ap.get_all_assurance_policies(c.server, c.token, assurance_type,
                                                     timeout=c.timeout)
        except AquaError as exc:
            if exc.status_code in (400, 404):    # a type this Aqua does not have
                continue
            raise
        found.extend({**policy, "assurance_type": assurance_type} for policy in policies)
    return found


def _assurance_policy_ops() -> _Ops:
    # Keys are "type/name" (KindDef.key). The API returns nothing on create and
    # update (HTTP 204), which AquasecClient.create already allows for.
    return _Ops(
        list=_all_assurance_policies,
        get=lambda c, key: _kubernetes_read_view(
            ap.get_assurance_policy(c.server, c.token, *key.split("/", 1), timeout=c.timeout)),
        create=lambda c, body: ap.create_assurance_policy(c.server, c.token, body["assurance_type"],
                                                          _kubernetes_write_view(body),
                                                          timeout=c.timeout),
        update=lambda c, key, body: ap.update_assurance_policy(c.server, c.token, *key.split("/", 1),
                                                               _kubernetes_write_view(body),
                                                               timeout=c.timeout),
        delete=lambda c, key: ap.delete_assurance_policy(c.server, c.token, *key.split("/", 1),
                                                         missing_ok=True, timeout=c.timeout),
    )


#: Kinds this client can serve. A kind in the schema registry but not here is a
#: build error, reported clearly rather than as an AttributeError mid-run.
_OPERATIONS: dict[str, Callable[[], _Ops]] = {
    "RuntimePolicy": _runtime_policy_ops,
    "AssurancePolicy": _assurance_policy_ops,
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

    def list(self, kind: KindDef) -> list[dict]:
        try:
            return list(self._ops(kind).list(self))
        except ClientError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise _translate(exc, f"Listing {kind.kind} objects") from None

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
        # Aqua returns the complete runtime policy on create (verified live) and
        # nothing for an assurance policy (204). Read it back then, so the
        # caller gets the server's view, including its numeric id.
        if isinstance(created, dict):
            return created
        qualifier = body.get(kind.qualifier_field) if kind.qualifier_field else None
        return self.get(kind, f"{qualifier}/{name}" if qualifier else name) or {}

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
    # No redirects: a console that sends the sign-in elsewhere gets an error, not the
    # password.
    set_request_defaults(verify=settings.verify, timeout=settings.timeout, allow_redirects=False)

    credentials = settings.credentials
    token = sign_in(credentials)

    # On a 401 mid-run (token expiry on a large tenant), sign in again with the
    # same credentials rather than failing the whole reconcile.
    set_token_provider(lambda: sign_in(credentials))

    return AquasecClient(_console_url(credentials, token), token, settings.timeout)
