import pytest
from diagnostic_browser.policy import Scope, normalize, UnsafeEvent, network_code

@pytest.mark.parametrize('url',[
  'https://example.org/','https://api.example.org/api/x?token=TEST','https://a.b.example.org/js/app.js'])
def test_allowed(url):assert Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')).allowed(url)
@pytest.mark.parametrize('url',[
  'https://example.org.evil.net','https://evilexample.org','https://okta.com','https://login.okta.com',
  'https://example.org@evil.net','http://example.org/','file:///etc/passwd',
  'https://user:password@example.org','https://example.org.evil.net?x=example.org'])
def test_denied(url):assert not Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')).allowed(url)

def test_url_redaction():
    p=Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org'))
    assert p.category('https://a.example.org/api/patient/MY_SECRET?token=AABB')=='api'
    assert p.category('https://a.example.org/john_smith')=='unclassified'
    assert p.category('https://login.okta.com/secret') is None

def test_local_test_only_when_explicit():
    assert Scope(test_local=True).allowed('http://127.0.0.1:9080/')
    assert not Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')).allowed('http://127.0.0.1:9080/')
    assert not Scope(test_local=True).allowed('http://localhost:9080/')

@pytest.mark.parametrize('f',[
  {'token':'secret'}, {'url':'https://example.org/?password=X'}, {'detail_code':'SECRET_FROM_APP'},
  {'status':200,'header':'Bearer XYZ'}, {'status':True},{'route':'patient/Alice'},
  {'method':'P@SSWORD'}, {'error_class':'SupersecretUserError'}])
def test_reject_unsafe_fields(f):
    with pytest.raises(UnsafeEvent):normalize('http_error','error',f)

def test_whitelisted_fields():
    result=normalize('http_error','error',{'status':500,'route':'api','method':'GET'})
    assert result[2]=={'status':500,'route':'api','method':'GET'}

def test_network_error_scrubbing():
    assert network_code('net::ERR_CONNECTION_RESET with secret!')=='ERR_CONNECTION_RESET'
    assert network_code('net::ERR_PATIENT_MARY')=='ERR_OTHER'
