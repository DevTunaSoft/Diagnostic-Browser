"""Local, intentionally faulty synthetic website; NEVER used against production."""
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse
lab=FastAPI(docs_url=None,openapi_url=None)
@lab.get('/',response_class=HTMLResponse)
def home():
    return '''<!DOCTYPE html><html><head><title>Local Synthetic Fault Lab</title></head><body><h1>Synthetic Fault Lab</h1><button id="trigger">Generate JavaScript failure</button><script>document.getElementById('trigger').onclick=()=>{throw new TypeError('FAKE_PASSWORD_SEED_91 Secret must never be saved')};</script></body></html>'''
@lab.get('/api/fail')
def fail():return PlainTextResponse('FAKE_PATIENT_SEED_52',status_code=500)
@lab.get('/api/forbidden')
def forbidden():return PlainTextResponse('fake token in body',status_code=403)
@lab.websocket('/socket.io/live')
async def ws(websocket:WebSocket):
    await websocket.accept();await websocket.send_text('FAKE_BEARER_TOKEN_SEED_43');await websocket.close()
