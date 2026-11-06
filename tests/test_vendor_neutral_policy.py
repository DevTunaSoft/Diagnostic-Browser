"""Production scope is opt-in and cannot be widened by untrusted URLs."""
import pytest
from diagnostic_browser.policy import Scope


def test_production_scope_defaults_to_disabled(monkeypatch):
    monkeypatch.delenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS', raising=False)
    assert not Scope.configured().allowed('https://app.example.org/api/a')


def test_explicit_authorization_only(monkeypatch):
    monkeypatch.setenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS', 'app.example.org')
    scope = Scope.configured()
    assert scope.allowed('https://app.example.org/api/a')
    assert not scope.allowed('https://other.example.org/api/a')
    assert not scope.allowed('http://app.example.org/api/a')
    assert not scope.allowed('https://app.example.org:8443/api/a')
    assert not scope.allowed('https://login.app.example.org/api/a')
    assert not scope.allowed('https://app.example.org/oauth2/authorize')


@pytest.mark.parametrize('value', ['*.example.org', 'localhost', '127.0.0.1', 'example.org,127.0.0.1', 'a..b', 'invalid host'])
def test_bad_host_configuration_rejected(monkeypatch, value):
    monkeypatch.setenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS', value)
    with pytest.raises(ValueError):
        Scope.configured()


def test_test_local_does_not_expand_production_scope():
    assert Scope(test_local=True).allowed('http://127.0.0.1:7777/api/a')
    assert not Scope().allowed('http://127.0.0.1:7777/api/a')
