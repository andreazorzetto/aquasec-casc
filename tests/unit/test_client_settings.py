"""Connection settings from the environment or a saved profile."""

from __future__ import annotations

import os

import pytest

from aquasec_casc.client.settings import (
    DEFAULT_METHODS,
    DEFAULT_TIMEOUT,
    ONPREM,
    SAAS_KEY,
    SAAS_USER,
    ConfigError,
    env_has_credentials,
    resolve_settings,
    settings_from_env,
    settings_from_profile,
)

SECRET = "s3cr3t-api-secret-value"
PASSWORD = "hunter2-password-value"
KEY = "api-key-value-123"

SAAS_KEY_ENV = {
    "AQUA_API_KEY": KEY,
    "AQUA_API_SECRET": SECRET,
    "AQUA_API_ENDPOINT": "https://eu-1.api.cloudsploit.com/",
    "AQUA_ROLE": "api_admin_role",
}


# --------------------------------------------------------------------------- #
# Sign-in mode
# --------------------------------------------------------------------------- #

def test_saas_api_key():
    s = settings_from_env(SAAS_KEY_ENV)
    c = s.credentials
    assert c.mode == SAAS_KEY
    assert c.api_endpoint == "https://eu-1.api.cloudsploit.com"   # trailing slash dropped
    assert c.methods == DEFAULT_METHODS == "ANY:*"
    assert c.console_url is None                                  # read from the token later


def test_saas_api_key_reports_every_missing_variable():
    with pytest.raises(ConfigError) as exc:
        settings_from_env({"AQUA_API_KEY": KEY})
    message = str(exc.value)
    for name in ("AQUA_API_SECRET", "AQUA_API_ENDPOINT", "AQUA_ROLE"):
        assert name in message


def test_saas_user():
    c = settings_from_env({"AQUA_USER": "me@example.com", "AQUA_PASSWORD": PASSWORD,
                           "AQUA_API_ENDPOINT": "https://eu-1.api.cloudsploit.com"}).credentials
    assert c.mode == SAAS_USER


def test_onprem_user():
    c = settings_from_env({"AQUA_USER": "administrator", "AQUA_PASSWORD": PASSWORD,
                           "AQUA_URL": "aqua.internal:8443/"}).credentials
    assert c.mode == ONPREM
    assert c.console_url == "https://aqua.internal:8443"          # normalised


def test_user_without_password():
    with pytest.raises(ConfigError, match="AQUA_PASSWORD"):
        settings_from_env({"AQUA_USER": "u", "AQUA_URL": "https://aqua.internal"})


def test_user_without_any_location():
    with pytest.raises(ConfigError, match="AQUA_URL"):
        settings_from_env({"AQUA_USER": "u", "AQUA_PASSWORD": PASSWORD})


def test_key_and_user_together_is_ambiguous():
    env = dict(SAAS_KEY_ENV, AQUA_USER="u", AQUA_PASSWORD=PASSWORD)
    with pytest.raises(ConfigError, match="unambiguous"):
        settings_from_env(env)


def test_no_credentials_explains_every_option():
    with pytest.raises(ConfigError) as exc:
        settings_from_env({})
    message = str(exc.value)
    assert "SaaS, API key" in message and "On-prem" in message and "--profile" in message


def test_blank_and_quoted_values_are_treated_as_unset_or_unquoted():
    env = dict(SAAS_KEY_ENV, AQUA_ROLE='"api_admin_role"', AQUA_URL="   ")
    c = settings_from_env(env).credentials
    assert c.role == "api_admin_role"
    assert c.console_url is None


# --------------------------------------------------------------------------- #
# TLS and timeout
# --------------------------------------------------------------------------- #

def test_tls_verification_is_on_by_default():
    assert settings_from_env(SAAS_KEY_ENV).verify is True


def test_a_ca_bundle(tmp_path):
    ca = tmp_path / "internal-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert settings_from_env(dict(SAAS_KEY_ENV, AQUA_CA_BUNDLE=str(ca))).verify == str(ca)


def test_a_missing_ca_bundle_fails_early_not_at_the_first_request():
    with pytest.raises(ConfigError, match="not a file"):
        settings_from_env(dict(SAAS_KEY_ENV, AQUA_CA_BUNDLE="/nope/ca.pem"))


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes"])
def test_insecure_is_an_explicit_choice(value):
    assert settings_from_env(dict(SAAS_KEY_ENV, AQUA_TLS_INSECURE=value)).verify is False


def test_insecure_and_a_ca_bundle_together_is_contradictory(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    with pytest.raises(ConfigError, match="Choose one"):
        settings_from_env(dict(SAAS_KEY_ENV, AQUA_CA_BUNDLE=str(ca), AQUA_TLS_INSECURE="true"))


def test_timeout():
    assert settings_from_env(SAAS_KEY_ENV).timeout == DEFAULT_TIMEOUT
    assert settings_from_env(dict(SAAS_KEY_ENV, AQUA_TIMEOUT="90")).timeout == 90.0
    with pytest.raises(ConfigError):
        settings_from_env(dict(SAAS_KEY_ENV, AQUA_TIMEOUT="soon"))
    with pytest.raises(ConfigError):
        settings_from_env(dict(SAAS_KEY_ENV, AQUA_TIMEOUT="0"))


# --------------------------------------------------------------------------- #
# Secrets never surface
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("env", [
    SAAS_KEY_ENV,
    {"AQUA_USER": "u", "AQUA_PASSWORD": PASSWORD, "AQUA_URL": "https://aqua.internal"},
])
def test_repr_and_describe_never_show_secrets(env):
    s = settings_from_env(env)
    for text in (repr(s), repr(s.credentials), s.credentials.describe()):
        for secret in (SECRET, PASSWORD, KEY):
            assert secret not in text


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #

class FakeConfigManager:
    def __init__(self, profiles, default="lab"):
        self.profiles = profiles
        self.default = default

    def get_default_profile(self):
        return self.default

    def list_profiles(self):
        return list(self.profiles)

    def load_config(self, name):
        return self.profiles[name][0]

    def decrypt_credentials(self, name):
        return self.profiles[name][1]


PROFILES = {
    "lab": ({"auth_method": "api_keys", "api_endpoint": "https://eu-1.api.cloudsploit.com",
             "csp_endpoint": "https://tenant.cloud.aquasec.com", "api_role": "admin",
             "api_methods": "ANY:*"},
            {"api_key": KEY, "api_secret": SECRET}),
    "saas-user": ({"auth_method": "user_pass", "api_endpoint": "https://eu-1.api.cloudsploit.com",
                   "csp_endpoint": "https://tenant.cloud.aquasec.com"},
                  {"username": "me@example.com", "password": PASSWORD}),
    "onprem": ({"auth_method": "user_pass", "csp_endpoint": "http://aqua.internal:8080"},
               {"username": "administrator", "password": PASSWORD}),
}


def test_profile_api_keys():
    c = settings_from_profile("lab", env={}, config_manager=FakeConfigManager(PROFILES)).credentials
    assert c.mode == SAAS_KEY and c.api_key == KEY and c.role == "admin"


def test_profile_saas_user_and_onprem():
    cm = FakeConfigManager(PROFILES)
    assert settings_from_profile("saas-user", env={}, config_manager=cm).credentials.mode == SAAS_USER
    onprem = settings_from_profile("onprem", env={}, config_manager=cm).credentials
    assert onprem.mode == ONPREM and onprem.console_url == "http://aqua.internal:8080"


def test_profile_defaults_to_the_saved_default():
    s = settings_from_profile(None, env={}, config_manager=FakeConfigManager(PROFILES, default="onprem"))
    assert s.credentials.mode == ONPREM


def test_unknown_profile_lists_what_exists():
    with pytest.raises(ConfigError) as exc:
        settings_from_profile("nope", env={}, config_manager=FakeConfigManager(PROFILES))
    assert "lab" in str(exc.value) and "onprem" in str(exc.value)


def test_profile_tls_still_comes_from_the_environment():
    s = settings_from_profile("lab", env={"AQUA_TLS_INSECURE": "true"},
                              config_manager=FakeConfigManager(PROFILES))
    assert s.verify is False


def test_reading_a_profile_does_not_copy_credentials_into_the_environment(monkeypatch):
    """The library's own loader exports them to os.environ; this must not."""
    for name in ("AQUA_KEY", "AQUA_SECRET", "AQUA_PASSWORD", "AQUA_USER"):
        monkeypatch.delenv(name, raising=False)
    settings_from_profile("lab", env={}, config_manager=FakeConfigManager(PROFILES))
    settings_from_profile("onprem", env={}, config_manager=FakeConfigManager(PROFILES))
    assert SECRET not in os.environ.values()
    assert PASSWORD not in os.environ.values()


# --------------------------------------------------------------------------- #
# Which source: --profile, then the environment, then the default profile
# --------------------------------------------------------------------------- #

API_ENV = {"AQUA_API_KEY": KEY, "AQUA_API_SECRET": SECRET, "AQUA_ROLE": "admin",
           "AQUA_API_ENDPOINT": "https://eu-1.api.cloudsploit.com"}


def test_an_explicit_profile_wins_over_the_environment():
    s = resolve_settings("onprem", env=API_ENV, config_manager=FakeConfigManager(PROFILES))
    assert s.credentials.mode == ONPREM and s.source == "profile 'onprem'"


def test_the_environment_wins_over_the_default_profile():
    """CI and Argo CD set variables; a stray profile on the machine must not matter."""
    s = resolve_settings(None, env=API_ENV, config_manager=FakeConfigManager(PROFILES))
    assert s.source == "environment"


def test_with_neither_the_default_profile_is_used():
    s = resolve_settings(None, env={}, config_manager=FakeConfigManager(PROFILES, default="onprem"))
    assert s.source == "profile 'onprem'" and s.credentials.mode == ONPREM


def test_a_partial_environment_is_an_error_not_a_fall_through():
    with pytest.raises(ConfigError, match="AQUA_PASSWORD"):
        resolve_settings(None, env={"AQUA_USER": "me"}, config_manager=FakeConfigManager(PROFILES))


def test_nothing_at_all_points_at_setup():
    with pytest.raises(ConfigError, match="aquasec-casc setup"):
        resolve_settings(None, env={}, config_manager=FakeConfigManager({}))


def test_tls_settings_alone_do_not_count_as_credentials():
    assert not env_has_credentials({"AQUA_URL": "https://x", "AQUA_TLS_INSECURE": "true"})
