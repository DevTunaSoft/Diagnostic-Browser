import pytest
from diagnostic_browser.policy import Scope


def test_capture_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS', raising=False)
    scope = Scope.configured()
    assert not scope.allowed('https://example.org/api')


def test_explicit_host_only(monkeypatch):
    monkeypatch.setenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS','example.org,api.example.org')
    scope = Scope.configured()
    assert scope.allowed('https://example.org/api')
    assert scope.allowed('wss://api.example.org/socket.io/')
    assert not scope.allowed('https://evil.example.org/api')
    assert not scope.allowed('https://example.org.evil.test/api')
    assert not scope.allowed('https://login.example.org/api')
    assert not scope.allowed('https://example.org/login')
    assert not scope.allowed('http://example.org/api')
    assert not scope.allowed('https://example.org:444/api')


@pytest.mark.parametrize('host', ['*','127.0.0.1','localhost','localhost.localhost','bad..org','a'*64+'.org','a.org:444','-bad.org'])
def test_reject_bad_config(monkeypatch,host):
    monkeypatch.setenv('DIAGNOSTIC_BROWSER_ALLOWED_HOSTS',host)
    with pytest.raises(ValueError):Scope.configured()
