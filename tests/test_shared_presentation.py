import base64
import json
from urllib.parse import unquote, urlsplit

import pytest

from shared_manager.agent import AgentError
from shared_manager.presentation import display_links


def sample():
    return {"vless": "vless://uuid@proxy.example:6666?security=reality#internal-node-id",
            "vmess": "vmess://" + base64.b64encode(json.dumps({"add": "proxy.example", "port": "7777", "id": "uuid", "ps": "internal-node-id"}).encode()).decode(),
            "protocolsAll": {"socksAcceleration": "socks://dTpw@proxy.example:9999#internal-node-id"}}


def test_public_labels_preserve_auth_and_replace_internal_names():
    links = display_links(sample(), "住宅 A")
    assert len(links) == 3
    assert unquote(urlsplit(links[0]["uri"]).fragment) == "住宅 A · VLESS"
    assert urlsplit(links[0]["uri"]).netloc == "uuid@proxy.example:6666"
    assert "internal-node-id" not in str(links)
    vmess = json.loads(base64.b64decode(links[1]["uri"].split("://", 1)[1]))
    assert vmess["ps"] == "住宅 A · VMESS"
    assert vmess["id"] == "uuid" and vmess["port"] == "7777"
    assert urlsplit(links[2]["uri"]).netloc == "dTpw@proxy.example:9999"


@pytest.mark.parametrize("bad", ["vmess://not-json", "vmess://" + base64.b64encode(b"[]").decode(), "vmess://x\nsecond"])
def test_malformed_remote_links_are_not_published(bad):
    data = sample()
    data["vmess"] = bad
    with pytest.raises(AgentError):
        display_links(data, "连接 A")
