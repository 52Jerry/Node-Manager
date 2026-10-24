"""The opt-in transport requires auth, explicit actions and exact receipts."""
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from operation_api import PreparedAction, create_operation_router
from operations import Observation, Operation, OperationPreconditionFailed, OperationStore


class OperationApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store = OperationStore(self.temporary.name)
        self.operation = Operation("stable-op-1", "node:3", "EXTERNAL:3:9007199254740993",
                                   "customer:41", "ACCESS_DESIRED", 1, 1)
        self.payload = {"enabled": True, "existingUuid": "sensitive-uuid"}
        self.effects = []
        self.reads = []
        self.fail_after_effect = False
        self.unknown_readback = False
        self.business_blocked = False

        def authorize(x_token: str | None = Header(None)):
            if x_token != "test-only-token":
                raise HTTPException(401, "unauthorized")

        def prepare(operation, payload):
            if not isinstance(payload.get("enabled"), bool):
                raise ValueError("invalid request with sensitive data")

            def apply():
                if self.business_blocked:
                    raise OperationPreconditionFailed("BUSINESS_BLOCKED")
                self.effects.append(operation.operation_id)
                if self.fail_after_effect:
                    raise TimeoutError("sensitive-backend-message")

            def readback():
                self.reads.append(operation.operation_id)
                return Observation(operation.operation_id, operation.request_hash(payload),
                                   operation.generation, operation.desired_version,
                                   "UNKNOWN" if self.unknown_readback else "APPLIED")

            return PreparedAction(apply, readback)

        self.app = FastAPI()
        self.app.include_router(create_operation_router(self.store, "node:3", authorize,
                                                        {"ACCESS_DESIRED": prepare}))
        self.client = TestClient(self.app)
        self.headers = {"X-Token": "test-only-token"}

    def tearDown(self):
        self.client.close()
        self.temporary.cleanup()

    def body(self, operation=None, payload=None):
        operation = operation or self.operation
        payload = self.payload if payload is None else payload
        return {"operationId": operation.operation_id, "nodeId": operation.node_id,
                "assetKey": operation.asset_key, "ownerRef": operation.owner_ref,
                "action": operation.action, "generation": operation.generation,
                "desiredVersion": operation.desired_version, "requestHash": operation.request_hash(payload),
                "payload": payload}

    def post(self, body=None, path="/api/operations"):
        return self.client.post(path, json=self.body() if body is None else body, headers=self.headers)

    def test_transport_is_authenticated_and_requires_explicit_handler(self):
        self.assertEqual(401, self.client.post("/api/operations", json=self.body()).status_code)
        self.assertEqual([], self.effects)
        unknown = self.post(self.body(replace(self.operation, action="UNKNOWN")))
        self.assertEqual(422, unknown.status_code)
        self.assertIsNone(self.store.read(self.operation.operation_id))

    def test_exact_apply_replay_and_read_receipt_are_redacted_and_not_cached(self):
        response = self.post()
        replay = self.post()
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["success"])
        self.assertTrue(replay.json()["replayed"])
        self.assertEqual([self.operation.operation_id], self.effects)
        read = self.client.get("/api/operations/" + self.operation.operation_id, headers=self.headers)
        self.assertEqual("no-store, private", read.headers["cache-control"])
        self.assertEqual("APPLIED", read.json()["status"])
        self.assertNotIn("sensitive-uuid", read.text)
        self.assertNotIn("payload", read.json())

    def test_wrong_node_hash_or_changed_payload_cannot_mutate(self):
        wrong_node = self.body(replace(self.operation, node_id="node:4"))
        self.assertEqual(409, self.post(wrong_node).status_code)
        wrong_hash = self.body()
        wrong_hash["requestHash"] = "0" * 64
        self.assertEqual(409, self.post(wrong_hash).status_code)
        self.post()
        self.assertEqual(409, self.post(self.body(payload={"enabled": False})).status_code)
        self.assertEqual([self.operation.operation_id], self.effects)

    def test_missing_operation_readback_does_not_create_or_apply(self):
        response = self.post(path="/api/operations/stable-op-1/readback")
        self.assertEqual(404, response.status_code)
        self.assertEqual([], self.effects)
        self.assertEqual([], self.reads)
        self.assertIsNone(self.store.read(self.operation.operation_id))

    def test_remote_success_timeout_readback_only_does_not_reapply(self):
        self.fail_after_effect = True
        response = self.post()
        self.assertEqual(202, response.status_code)
        self.assertFalse(response.json()["success"])
        self.assertEqual("UNKNOWN", response.json()["status"])
        readback = self.post(path="/api/operations/stable-op-1/readback")
        self.assertEqual(200, readback.status_code)
        self.assertEqual("APPLIED", readback.json()["status"])
        self.assertEqual([self.operation.operation_id], self.effects)
        self.assertNotIn("sensitive", readback.text)

    def test_unknown_readback_stays_unknown_and_old_command_is_rejected_after_revoke(self):
        self.fail_after_effect = True
        self.post()
        self.unknown_readback = True
        uncertain = self.post(path="/api/operations/stable-op-1/readback")
        self.assertEqual(202, uncertain.status_code)
        self.fail_after_effect = self.unknown_readback = False
        newer = replace(self.operation, operation_id="revoke-v2", desired_version=2)
        self.assertEqual(200, self.post(self.body(newer, {"enabled": False})).status_code)
        old = self.post()
        self.assertEqual(409, old.status_code)
        self.assertEqual("STALE_VERSION", old.json()["reason"])
        self.assertEqual(["stable-op-1", "revoke-v2"], self.effects)

    def test_explicit_business_block_is_rejected_and_not_technical_unknown(self):
        self.business_blocked = True
        response = self.post()
        self.assertEqual(409, response.status_code)
        self.assertEqual("REJECTED", response.json()["status"])
        self.assertEqual("BUSINESS_BLOCKED", response.json()["reason"])
        self.assertFalse(response.json()["success"])
        self.assertEqual([], self.effects)
        self.business_blocked = False
        self.assertEqual(409, self.post().status_code)  # A new desired version is required.
        self.assertEqual([], self.effects)

    def test_noncanonical_numbers_invalid_types_and_path_id_are_rejected(self):
        self.assertEqual(422, self.post(self.body(payload={"enabled": True, "value": 0.1})).status_code)
        body = self.body()
        body["generation"] = "1"
        self.assertEqual(422, self.post(body).status_code)
        self.assertEqual(409, self.post(path="/api/operations/other/readback").status_code)
        self.assertEqual([], self.effects)


if __name__ == "__main__":
    unittest.main()
