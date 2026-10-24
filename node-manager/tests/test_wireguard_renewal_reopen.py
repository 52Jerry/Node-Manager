"""Offline ABSENT/EXISTING_EXACT checks for the fixed subscription 2359 reopen."""
import copy
import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import unittest

from test_wireguard_migration_recovery import RecoveryFixture, digest, main
import wireguard_renewal_reopen as reopen
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient


class ReopenFixture(RecoveryFixture):
    def setUp(self):
        super().setUp()
        previous_target = self.target
        self.target, self.source = reopen.TARGET, reopen.PREVIOUS
        self.target_tag = reopen.manager.USER_OUTBOUND_PREFIX + self.target
        self.auth_name = reopen.manager._auth_name(self.target)
        self.registry["users"][self.target] = self.registry["users"].pop(previous_target)
        self.registry["users"][self.target].pop("residentialOwnershipMigration")
        for inbound in self.data["inbounds"]:
            inbound["users"][0]["name"] = self.auth_name
        self.data["outbounds"][0]["tag"] = self.target_tag
        self.data["inbounds"].append({"type":"socks","tag":reopen.adoption.config.singbox.socks_tag,
            "users":[{"username":self.target,"password":self.uuid}]})
        self.data["route"]["rules"] = [{"auth_user": [self.auth_name,self.target], "outbound": self.target_tag}]
        self.old.update(peerId=reopen.PEER_ID, nodeUserId=self.target, status="ACTIVE", stateReason=None)
        self.runtime["peers"] = []
        self.request = reopen.ReopenCheck(subscriptionId=2359, resourceId=2363, accessProfileId=2359,
            previousNodeUserId=self.source, targetUserId=self.target, uuidSha256=digest(self.uuid),
            proxySha256=digest(json.dumps(self.identity,ensure_ascii=False,separators=(",", ":"))),
            expiresAt=self.expiry)

    def evaluate(self):
        before = copy.deepcopy((self.data,self.registry,self.runtime))
        result = reopen.evaluate(self.request,self.data,self.registry,self.runtime)
        self.assertEqual((self.data,self.registry,self.runtime),before)
        self.assertEqual(set(result["checks"]),set(reopen.CHECK_NAMES))
        self.assertEqual(len(result["checks"]),14)
        self.assert_redacted(result)
        return result

    def make_absent(self):
        self.registry["users"] = {}
        for inbound in self.data["inbounds"]:
            inbound["users"] = []
        self.data["outbounds"] = []
        self.data["route"]["rules"] = []

    def assert_rejected(self,check):
        result = self.evaluate()
        self.assertFalse(result["ready"],result)
        self.assertFalse(result["checks"][check],result)

    def add_foreign_proxy(self,**changes):
        outbound = {"type":"socks","tag":reopen.manager.USER_OUTBOUND_PREFIX+"foreign",
                    "server":self.identity[0],"server_port":self.identity[1],
                    "username":self.username,"password":self.password,**changes}
        self.data["outbounds"].append(outbound)


class AbsentReopenTests(ReopenFixture):
    def setUp(self):
        super().setUp()
        self.make_absent()

    def test_absent_scope_is_ready_redacted_and_read_only(self):
        result = self.evaluate()
        self.assertEqual(result["phase"],"ABSENT")
        self.assertTrue(result["ready"],result)

    def test_same_endpoint_different_complete_credentials_are_preserved(self):
        self.add_foreign_proxy(username="another-user",password="another-password")
        self.assertTrue(self.evaluate()["ready"])

    def test_wrong_scope_never_passes(self):
        for field,value in (("subscriptionId",2360),("resourceId",2364),("accessProfileId",2360),
                            ("previousNodeUserId","different"),("targetUserId","primary-2360")):
            with self.subTest(field=field):
                previous=self.request
                self.request=self.request.model_copy(update={field:value})
                self.assert_rejected("scopeExact")
                self.request=previous

    def test_old_registry_or_expired_registry_prevents_reopen(self):
        for kind in ("users","expiredUsers"):
            with self.subTest(kind=kind):
                self.registry.setdefault(kind,{})[self.source]={"expiresAt":self.expiry.isoformat()}
                self.assert_rejected("previousOwnerAbsent")
                self.registry[kind].pop(self.source)

    def test_old_authentication_prevents_reopen(self):
        self.data["inbounds"][0]["users"].append({"name":self.source,"uuid":"different"})
        self.assert_rejected("previousOwnerAbsent")

    def test_old_outbound_or_route_prevents_reopen(self):
        self.data["outbounds"].append({"type":"direct","tag":reopen.manager.USER_OUTBOUND_PREFIX+self.source})
        self.assert_rejected("previousOwnerAbsent")
        self.data["outbounds"] = []
        self.data["route"]["rules"].append({"auth_user":[self.source],"outbound":"direct"})
        self.assert_rejected("previousOwnerAbsent")

    def test_old_wg_even_revoked_prevents_reopen(self):
        self.runtime["peers"].append({**self.old,"nodeUserId":self.source,"status":"REVOKED"})
        self.assert_rejected("previousOwnerAbsent")

    def test_partial_target_registry_is_not_treated_as_absent(self):
        self.registry["users"][self.target]={"expiresAt":self.expiry.isoformat()}
        self.assertEqual(self.evaluate()["phase"],"EXISTING_EXACT")
        self.assert_rejected("canonicalStateConsistent")

    def test_expired_target_registry_is_not_treated_as_absent(self):
        self.registry["expiredUsers"]={self.target:{"expiresAt":self.expiry.isoformat()}}
        self.assert_rejected("canonicalStateConsistent")
        self.assert_rejected("registryScopeMatches")

    def test_partial_target_auth_or_outbound_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name":self.auth_name,"uuid":self.uuid})
        self.assert_rejected("canonicalStateConsistent")
        self.data["inbounds"][0]["users"] = []
        self.data["outbounds"].append({"type":"direct","tag":self.target_tag})
        self.assert_rejected("canonicalStateConsistent")

    def test_dangling_target_route_or_selector_prevents_create(self):
        self.data["route"]["rules"].append({"auth_user":[self.auth_name],"outbound":self.target_tag})
        self.assert_rejected("canonicalStateConsistent")
        self.data["route"]["rules"] = []
        self.data["outbounds"].append({"type":"selector","tag":"shared","outbounds":[self.target_tag]})
        self.assert_rejected("canonicalStateConsistent")

    def test_shared_full_proxy_blocks_even_without_registered_owner(self):
        self.add_foreign_proxy()
        self.assert_rejected("proxyMatches")
        self.assert_rejected("proxyUnique")

    def test_canonical_equivalent_full_proxy_is_also_blocked(self):
        self.add_foreign_proxy(server="["+self.identity[0]+"]")
        self.assert_rejected("proxyUnique")

    def test_shared_original_uuid_or_trojan_password_blocks(self):
        self.data["inbounds"][0]["users"].append({"name":"foreign","uuid":self.uuid})
        self.assert_rejected("uuidMatches")
        self.data["inbounds"][0]["users"] = []
        self.data["inbounds"][2]["users"].append({"name":"foreign","password":self.uuid})
        self.assert_rejected("uuidMatches")

    def test_foreign_registry_alias_claiming_canonical_name_blocks(self):
        self.registry["users"]["foreign"]={"socksUsername":self.target}
        self.assert_rejected("authenticationUnique")

    def test_target_wg_identity_without_user_is_rejected(self):
        self.runtime["peers"].append(self.old)
        self.assert_rejected("canonicalStateConsistent")

    def test_reserved_peer_id_under_another_owner_is_rejected(self):
        self.runtime["peers"].append({**self.old,"nodeUserId":"foreign"})
        self.assert_rejected("wireguardStateCompatible")

    def test_expired_request_is_rejected(self):
        self.request=self.request.model_copy(update={"expiresAt":datetime.now(timezone.utc)-timedelta(days=1)})
        self.assert_rejected("entitlementCurrent")

    def test_unready_runtime_is_rejected(self):
        self.runtime["routingReady"]=False
        self.assert_rejected("runtimeReady")


class ExistingReopenTests(ReopenFixture):
    def test_exact_existing_target_is_ready(self):
        result=self.evaluate()
        self.assertEqual(result["phase"],"EXISTING_EXACT")
        self.assertTrue(result["ready"],result)

    def test_exact_existing_with_wg_is_allowed_for_java_db_identity_check(self):
        self.runtime["peers"].append(self.old)
        self.assertTrue(self.evaluate()["ready"])

    def test_existing_keeps_same_endpoint_foreign_credentials(self):
        self.add_foreign_proxy(username="another",password="another-password")
        self.assertTrue(self.evaluate()["ready"])

    def test_existing_scope_metadata_must_match(self):
        for field in ("resourceId","userIpResourceId","subscriptionId","accessProfileId"):
            with self.subTest(field=field):
                self.registry["users"][self.target][field]=999
                self.assert_rejected("registryScopeMatches")
                self.registry["users"][self.target].pop(field)

    def test_existing_wrong_scope_request_is_rejected(self):
        self.request=self.request.model_copy(update={"resourceId":999})
        self.assert_rejected("scopeExact")

    def test_existing_with_old_owner_remaining_is_rejected(self):
        self.registry["users"][self.source]={"expiresAt":self.expiry.isoformat()}
        self.assert_rejected("previousOwnerAbsent")

    def test_existing_changed_proxy_is_rejected(self):
        self.data["outbounds"][0]["password"]="changed"
        self.assert_rejected("proxyMatches")

    def test_existing_incomplete_proxy_is_rejected(self):
        self.data["outbounds"][0]["password"]=""
        self.assert_rejected("canonicalStateConsistent")

    def test_existing_duplicate_full_proxy_is_rejected(self):
        self.add_foreign_proxy()
        self.assert_rejected("proxyUnique")

    def test_existing_uuid_mismatch_is_rejected(self):
        self.request=self.request.model_copy(update={"uuidSha256":digest("different")})
        self.assert_rejected("uuidMatches")

    def test_existing_shared_auth_uuid_is_rejected(self):
        self.data["inbounds"][0]["users"].append({"name":"foreign","uuid":self.uuid})
        self.assert_rejected("authenticationUnique")

    def test_exact_canonical_socks_credential_matches_create_intent(self):
        self.assertTrue(self.evaluate()["ready"])

    def test_changed_canonical_socks_password_rejects_existing_proof(self):
        self.data["inbounds"][3]["users"][0]["password"]="different-secret"
        self.assert_rejected("authenticationUnique")

    def test_each_required_protocol_missing_inbound_rejects_existing_proof(self):
        original=copy.deepcopy(self.data["inbounds"])
        for protocol in ("vless","vmess","socks"):
            with self.subTest(protocol=protocol):
                self.data["inbounds"]=[i for i in original if i["type"]!=protocol]
                self.assert_rejected("canonicalStateConsistent")
                self.assert_rejected("authenticationUnique")
        self.data["inbounds"]=original

    def test_each_required_protocol_missing_auth_rejects_existing_proof(self):
        for inbound in self.data["inbounds"]:
            if inbound["type"] not in {"vless","vmess","socks"}:continue
            with self.subTest(protocol=inbound["type"]):
                original=inbound["users"]
                inbound["users"]=[]
                self.assert_rejected("canonicalStateConsistent")
                self.assert_rejected("authenticationUnique")
                inbound["users"]=original

    def test_each_required_protocol_duplicate_auth_rejects_existing_proof(self):
        for inbound in self.data["inbounds"]:
            if inbound["type"] not in {"vless","vmess","socks"}:continue
            with self.subTest(protocol=inbound["type"]):
                inbound["users"].append(dict(inbound["users"][0]))
                self.assert_rejected("authenticationUnique")
                inbound["users"].pop()

    def test_each_required_protocol_duplicate_inbound_rejects_existing_proof(self):
        for inbound in list(self.data["inbounds"]):
            if inbound["type"] not in {"vless","vmess","socks"}:continue
            with self.subTest(protocol=inbound["type"]):
                duplicate=copy.deepcopy(inbound)
                duplicate["users"]=[]
                self.data["inbounds"].append(duplicate)
                self.assert_rejected("authenticationUnique")
                self.data["inbounds"].pop()

    def test_each_uuid_protocol_requires_original_uuid(self):
        for inbound in self.data["inbounds"]:
            if inbound["type"] not in {"vless","vmess"}:continue
            with self.subTest(protocol=inbound["type"]):
                inbound["users"][0]["uuid"]="different"
                self.assert_rejected("authenticationUnique")
                inbound["users"][0]["uuid"]=self.uuid

    def test_optional_trojan_can_be_absent(self):
        self.data["inbounds"]=[i for i in self.data["inbounds"] if i["type"]!="trojan"]
        self.assertTrue(self.evaluate()["ready"])

    def test_existing_auth_on_unmanaged_inbound_is_rejected(self):
        self.data["inbounds"][0]["tag"]="unmanaged"
        self.assert_rejected("authenticationUnique")

    def test_existing_route_shared_or_missing_is_rejected(self):
        self.data["route"]["rules"][0]["auth_user"].append("foreign")
        self.assert_rejected("routesOwned")
        self.data["route"]["rules"]=[]
        self.assert_rejected("routesOwned")

    def test_existing_expiry_cannot_be_extended_by_request(self):
        self.request=self.request.model_copy(update={"expiresAt":self.expiry+timedelta(seconds=1)})
        self.assert_rejected("entitlementCurrent")

    def test_existing_expired_or_disabled_owner_is_rejected(self):
        self.registry["users"][self.target]["expiresAt"]=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        self.assert_rejected("targetEligible")
        self.registry["users"][self.target]["expiresAt"]=self.expiry.isoformat()
        for key,value in (("accessEnabled",False),("accessBlocked",True),
                          ("enforcementTrafficBlocked",True),("expirationBlocked",True)):
            with self.subTest(key=key):
                self.registry["users"][self.target][key]=value
                self.assert_rejected("targetEligible")
                self.registry["users"][self.target].pop(key)

    def test_existing_reserved_peer_id_belongs_to_target_only(self):
        self.runtime["peers"].append({**self.old,"nodeUserId":"foreign"})
        self.assert_rejected("wireguardStateCompatible")


class ReopenEndpointTests(ReopenFixture):
    def setUp(self):
        super().setUp()
        app=FastAPI()
        app.add_exception_handler(RequestValidationError,main.validation_error_handler)
        app.include_router(reopen.router)
        self.client=TestClient(app)
        self.addCleanup(self.client.close)
        self.enterContext(patch.object(reopen.adoption.config.security,"token","offline-test-token"))
        self.enterContext(patch.object(reopen.adoption.config.security,"allowed_cidrs",""))
        self.enterContext(patch.object(reopen.manager,"_config_lock",side_effect=nullcontext))
        self.read_config=self.enterContext(patch.object(reopen.manager,"read_config",side_effect=lambda:copy.deepcopy(self.data)))
        self.read_registry=self.enterContext(patch.object(reopen.manager,"read_registry",side_effect=lambda:copy.deepcopy(self.registry)))
        self.read_runtime=self.enterContext(patch.object(reopen.wireguard,"status",side_effect=lambda:copy.deepcopy(self.runtime)))

    def post(self,headers=None,payload=None):
        return self.client.post("/api/wireguard/renewal-reopen/check",
            headers=headers if headers is not None else {"Authorization":"Bearer offline-test-token"},
            json=payload if payload is not None else self.request.model_dump(mode="json"))

    def test_both_phases_are_no_store_read_only_and_redacted(self):
        for phase in ("EXISTING_EXACT","ABSENT"):
            with self.subTest(phase=phase):
                if phase=="ABSENT":self.make_absent()
                response=self.post()
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.json()["phase"],phase)
                self.assertTrue(response.json()["ready"],response.json())
                self.assertEqual(set(response.json()["checks"]),set(reopen.CHECK_NAMES))
                self.assertEqual(response.headers.get("cache-control"),"no-store")
                self.assert_redacted(response.json())

    def test_missing_or_wrong_token_does_not_read(self):
        for headers in ({},{"Authorization":"Bearer wrong-token"}):
            self.assertIn(self.post(headers=headers).status_code,(401,403))
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_real_main_mount_requires_authentication(self):
        real_client=TestClient(main.app)
        self.addCleanup(real_client.close)
        for headers in ({},{"Authorization":"Bearer wrong-token"}):
            with self.subTest(headers=headers):
                response=real_client.post("/api/wireguard/renewal-reopen/check",headers=headers,
                    json=self.request.model_dump(mode="json"))
                self.assertIn(response.status_code,(401,403))
        self.read_config.assert_not_called()
        self.read_registry.assert_not_called()
        self.read_runtime.assert_not_called()

    def test_registry_change_fails_closed(self):
        changed=copy.deepcopy(self.registry)
        changed["users"][self.source]={}
        self.read_registry.side_effect=[copy.deepcopy(self.registry),changed]
        response=self.post()
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_config_change_fails_closed(self):
        changed=copy.deepcopy(self.data)
        changed["route"]["rules"]=[]
        self.read_config.side_effect=[copy.deepcopy(self.data),changed]
        response=self.post()
        self.assertFalse(response.json()["ready"])
        self.assertFalse(response.json()["checks"]["snapshotUnchanged"])

    def test_invalid_input_is_redacted(self):
        payload=self.request.model_dump(mode="json")
        payload["uuidSha256"]=self.password
        response=self.post(payload=payload)
        self.assertEqual(response.status_code,422)
        self.assert_redacted(response.json())
        self.read_config.assert_not_called()

    def test_runtime_error_is_redacted(self):
        self.read_runtime.side_effect=reopen.wireguard.WireguardError(self.password)
        response=self.post()
        self.assertEqual(response.status_code,503)
        self.assert_redacted(response.json())


if __name__=="__main__":
    unittest.main(verbosity=2)
