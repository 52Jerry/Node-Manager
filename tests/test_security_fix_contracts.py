"""Read-only recovery never invokes a mutation; management transport fails closed."""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from test_next_stage import main, idempotency


def test_receipt_reads_original_encrypted_result_and_does_not_execute():
    with tempfile.TemporaryDirectory() as directory, patch.object(idempotency, "STORE_PATH", Path(directory)/"receipts.json"):
        result, _ = idempotency.execute_idempotent("receipt-key", "delete-user", {"userId":"u1"}, lambda: {"success":True})
        before=idempotency.STORE_PATH.read_bytes()
        client=TestClient(main.app)
        body={"key":"receipt-key","operation":"delete-user","payload":{"userId":"u1"}}
        assert client.post('/api/agent/operation-receipt',json=body).status_code in (401,403)
        with patch.object(main,"delete_user_endpoint",side_effect=AssertionError("receipt must not mutate")):
            response=client.post('/api/agent/operation-receipt',json=body,headers={"Authorization":"Bearer test-token"})
        assert response.status_code==200,response.text
        assert response.json()=={"state":"CONFIRMED","result":result}
        assert 'no-store' in response.headers['cache-control']
        assert idempotency.STORE_PATH.read_bytes()==before
        body['payload']['userId']='another'
        assert client.post('/api/agent/operation-receipt',json=body,headers={"Authorization":"Bearer test-token"}).status_code==409


def test_missing_receipt_stays_unknown_and_invalid_identity_is_generic():
    with tempfile.TemporaryDirectory() as directory, patch.object(idempotency,"STORE_PATH",Path(directory)/"absent.json"):
        assert idempotency.lookup_receipt('missing','delete-user',{'userId':'u1'})=={'state':'UNKNOWN'}
        assert not idempotency.STORE_PATH.exists()
        response=TestClient(main.app).post('/api/agent/operation-receipt',json={"key":"missing","operation":"create-user","payload":{"socksPassword":"never-echo-me"}},headers={"Authorization":"Bearer test-token"})
        assert response.status_code==422
        assert 'never-echo-me' not in response.text


@pytest.mark.parametrize('url,bind,cidrs,allowed',[
    ('http://198.51.100.2:8088','0.0.0.0','10.0.0.1/32',False),
    ('https://node.example.com','0.0.0.0','',False),
    ('http://10.8.0.2:8088','10.8.0.2','10.8.0.1/32',True),
    ('https://node.example.com','127.0.0.1','',True),
    ('https://user:pass@node.example.com','127.0.0.1','',False),
])
def test_installer_transport_preflight(url,bind,cidrs,allowed):
    source=(Path(__file__).parents[1]/'install.sh').read_text(encoding='utf-8')
    code=re.search(r"python3 - <<'PY' \|\| fail[^\n]*\n(.*?)\nPY",source,re.S).group(1)
    env={**os.environ,'NODE_MANAGER_PUBLIC_URL':url,'NODE_MANAGER_BIND_ADDRESS':bind,'NODE_MANAGER_ALLOWED_CIDRS':cidrs,'CONTROL_PLANE_URL':'https://control.example.com'}
    outcome=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,text=True)
    assert (outcome.returncode==0)==allowed,outcome.stderr
