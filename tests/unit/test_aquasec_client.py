"""The aquasec-lib adapter, with the library mocked at the module boundary."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import requests
from aquasec.common import get_request_defaults, reset_request_defaults, set_token_provider
from aquasec.exceptions import ApiError, AuthenticationError

from aqua_casc.client import aquasec_client as ac
from aqua_casc.client.settings import ONPREM, SAAS_KEY, SAAS_USER, Credentials, Settings
from aqua_casc.reconcile.client import AquaClient, ClientError
from aqua_casc.schema import registry

PASSWORD = "hunter2-password-value"
SECRET = "s3cr3t-api-secret-value"
KIND = registry.get("RuntimePolicy")


@pytest.fixture(autouse=True)
def _reset_library_state():
    reset_request_defaults()
    set_token_provider(None)
    yield
    reset_request_defaults()
    set_token_provider(None)


def key_creds(**kw):
    base = dict(mode=SAAS_KEY, api_endpoint="https://eu-1.api.cloudsploit.com",
                api_key="k", api_secret=SECRET, role="admin")
    base.update(kw)
    return Credentials(**base)


ONPREM_CREDS = Credentials(mode=ONPREM, console_url="https://aqua.internal",
                           user="administrator", password=PASSWORD)


# --------------------------------------------------------------------------- #
# connect / sign-in
# --------------------------------------------------------------------------- #

@patch.object(ac, "get_console_urls_from_token", return_value={"console": "https://t.cloud.aquasec.com"})
@patch.object(ac, "api_auth", return_value="tok")
def test_connect_saas_key_reads_the_console_from_the_token(api_auth, _urls):
    client = ac.connect(Settings(credentials=key_creds(), verify=True, timeout=12))
    assert client.server == "https://t.cloud.aquasec.com"
    assert client.token == "tok" and client.timeout == 12
    args = api_auth.call_args.args
    assert args[2] == "https://eu-1.api.cloudsploit.com" and args[3] == "admin"
    assert args[4] == '["ANY:*"]'


@patch.object(ac, "api_auth", return_value="tok")
def test_connect_applies_tls_and_timeout_library_wide(_api_auth):
    ac.connect(Settings(credentials=key_creds(console_url="https://x"), verify="/ca.pem", timeout=7))
    assert get_request_defaults() == {"verify": "/ca.pem", "timeout": 7}


@patch.object(ac, "user_pass_onprem_auth", return_value="tok")
def test_connect_onprem(onprem):
    client = ac.connect(Settings(credentials=ONPREM_CREDS))
    assert client.server == "https://aqua.internal"
    assert onprem.call_args.args == ("administrator", PASSWORD, "https://aqua.internal")


@patch.object(ac, "user_pass_saas_auth", return_value="tok")
def test_connect_saas_user(saas_user):
    creds = Credentials(mode=SAAS_USER, console_url="https://x", api_endpoint="https://api",
                        user="me", password=PASSWORD)
    ac.connect(Settings(credentials=creds))
    assert saas_user.call_args.args == ("me", PASSWORD, "https://api")


@patch.object(ac, "user_pass_onprem_auth", return_value="tok")
def test_connect_registers_a_token_provider_that_signs_in_again(onprem):
    from aquasec import common
    ac.connect(Settings(credentials=ONPREM_CREDS))
    onprem.return_value = "tok2"
    assert common._token_provider() == "tok2"


@patch.object(ac, "user_pass_onprem_auth",
              side_effect=AuthenticationError("Authentication failed 401", status_code=401))
def test_sign_in_failure_is_a_client_error_without_the_password(_onprem):
    with pytest.raises(ClientError) as exc:
        ac.connect(Settings(credentials=ONPREM_CREDS))
    assert exc.value.status == 401
    assert "Sign-in failed" in str(exc.value)
    assert PASSWORD not in str(exc.value)
    assert "administrator" in str(exc.value)          # says *which* identity failed


@patch.object(ac, "api_auth", side_effect=requests.exceptions.SSLError("certificate verify failed"))
def test_an_untrusted_certificate_points_at_the_ca_bundle(_api_auth):
    with pytest.raises(ClientError) as exc:
        ac.connect(Settings(credentials=key_creds(console_url="https://x")))
    assert "AQUA_CA_BUNDLE" in str(exc.value)
    assert SECRET not in str(exc.value)


@patch.object(ac, "api_auth", side_effect=requests.exceptions.ConnectTimeout("timed out"))
def test_a_timeout_says_so(_api_auth):
    with pytest.raises(ClientError, match="AQUA_TIMEOUT"):
        ac.connect(Settings(credentials=key_creds(console_url="https://x")))


@patch.object(ac, "get_console_urls_from_token", return_value={})
@patch.object(ac, "api_auth", return_value="tok")
def test_no_console_url_anywhere_asks_for_aqua_url(_api_auth, _urls):
    from aqua_casc.client.settings import ConfigError
    with pytest.raises(ConfigError, match="AQUA_URL"):
        ac.connect(Settings(credentials=key_creds()))


# --------------------------------------------------------------------------- #
# The four verbs
# --------------------------------------------------------------------------- #

@pytest.fixture
def client():
    return ac.AquasecClient("https://t", "tok", 9)


def test_satisfies_the_reconciler_protocol(client):
    assert isinstance(client, AquaClient)


@patch.object(ac.rp, "get_runtime_policy", return_value={"name": "p"})
def test_get(get, client):
    assert client.get(KIND, "p") == {"name": "p"}
    assert get.call_args.args == ("https://t", "tok", "p")
    assert get.call_args.kwargs == {"timeout": 9}


@patch.object(ac.rp, "get_runtime_policy", return_value=None)
def test_get_missing_is_none(_get, client):
    assert client.get(KIND, "nope") is None


@patch.object(ac.rp, "create_runtime_policy", return_value={"name": "p", "id": 7})
def test_create_returns_the_server_object(_create, client):
    assert client.create(KIND, {"name": "p"})["id"] == 7


@patch.object(ac.rp, "get_runtime_policy", return_value={"name": "p", "id": 8})
@patch.object(ac.rp, "create_runtime_policy", return_value=None)
def test_create_reads_back_when_aqua_returns_no_body(_create, _get, client):
    assert client.create(KIND, {"name": "p"})["id"] == 8


@patch.object(ac.rp, "update_runtime_policy", return_value=None)
def test_update_sends_the_full_body_to_the_named_policy(update, client):
    client.update(KIND, "p", {"name": "p", "enforce": False})
    assert update.call_args.args == ("https://t", "tok", "p", {"name": "p", "enforce": False})


@patch.object(ac.rp, "delete_runtime_policy", return_value=True)
def test_delete_tolerates_an_already_missing_policy(delete, client):
    client.delete(KIND, "p")
    assert delete.call_args.kwargs["missing_ok"] is True


@patch.object(ac.rp, "update_runtime_policy",
              side_effect=ApiError("Failed to update runtime policy 'p': HTTP 500 - boom", status_code=500))
def test_library_errors_become_client_errors_with_the_status(_update, client):
    with pytest.raises(ClientError) as exc:
        client.update(KIND, "p", {"name": "p"})
    assert exc.value.status == 500
    assert "Updating RuntimePolicy 'p'" in str(exc.value)


@patch.object(ac.rp, "get_runtime_policy", side_effect=requests.exceptions.ConnectionError("refused"))
def test_connection_failures_become_client_errors(_get, client):
    with pytest.raises(ClientError, match="could not connect"):
        client.get(KIND, "p")


def test_an_unsupported_kind_is_a_clear_error(client):
    from dataclasses import replace
    other = replace(KIND, kind="EnforcerGroup")
    with pytest.raises(ClientError, match="not supported by this client yet"):
        client.get(other, "g")


def test_every_registered_kind_is_served_by_the_client():
    """A kind in the schema registry the client cannot serve is a build error."""
    assert set(registry.kinds()) <= set(ac.supported_kinds())


@patch.object(ac.rp, "get_all_runtime_policies",
              return_value=[{"name": "a", "description": "x", "is_ootb_policy": False}])
def test_list_is_one_paginated_call(get_all, client):
    """The runtime list response carries name, description and the built-in flag."""
    assert client.list(KIND) == [{"name": "a", "description": "x", "is_ootb_policy": False}]
    assert get_all.call_args.args == ("https://t", "tok")
    assert get_all.call_args.kwargs == {"timeout": 9}


@patch.object(ac.rp, "get_all_runtime_policies", side_effect=ApiError("HTTP 403", status_code=403))
def test_list_failures_become_client_errors(_get_all, client):
    with pytest.raises(ClientError) as exc:
        client.list(KIND)
    assert exc.value.status == 403 and "Listing RuntimePolicy" in str(exc.value)
