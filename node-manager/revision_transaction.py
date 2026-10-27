"""Durable config/registry/revision transactions. All entry points share manager's lock.

The journal is an undo record, not evidence that a revision ran. A committed
receipt proves file readback and a successful reload, not remote proxy reachability.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from singbox import manager
import revision as rev


def _paths():
    return {"config": rev.CONFIG_PATH, "registry": manager.REGISTRY_PATH,
            "state": rev.STATE_PATH, "current": rev.CURRENT_PATH,
            "lastGood": rev.LAST_GOOD_PATH, "bundle": rev.CURRENT_BUNDLE_PATH,
            "lastGoodBundle": rev.LAST_GOOD_BUNDLE_PATH}


def _sync_dir(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic(path, data, mode=0o600, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staged, mode)
        if owner and hasattr(os, "chown"):
            os.chown(staged, *owner)
        os.replace(staged, path)
        _sync_dir(path.parent)
    finally:
        staged.unlink(missing_ok=True)


def _json_write(path, value):
    _atomic(path, (rev._canonical_json(value) + "\n").encode("utf-8"))


def _json_read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _capture(path):
    if not path.exists():
        return None
    stat = path.stat()
    return {"bytes": base64.b64encode(path.read_bytes()).decode("ascii"),
            "mode": stat.st_mode & 0o777, "owner": [stat.st_uid, stat.st_gid]}


def _restore(path, record):
    if record is None:
        path.unlink(missing_ok=True)
        if path.parent.exists():
            _sync_dir(path.parent)
    else:
        _atomic(path, base64.b64decode(record["bytes"], validate=True),
                record["mode"], record.get("owner"))


def bundle(revision_id, data, registry):
    return {"version": 2, "nodeId": str(rev.config.node.id),
            "revisionId": revision_id, "config": data, "registry": registry}


def digest(value):
    return rev._sha256(rev._canonical_json(value))


def _observed(revision_id):
    return bundle(revision_id, _json_read(rev.CONFIG_PATH), _json_read(manager.REGISTRY_PATH))


def assert_no_pending_transaction():
    # Called with manager's lock held; never acquire the same flock recursively.
    import runtime_publication
    runtime_publication.assert_no_pending()
    if rev.JOURNAL_PATH.exists():
        raise manager.SingboxConfigError("revision recovery required before configuration mutations")


def _remove_journal():
    rev.JOURNAL_PATH.unlink(missing_ok=True)
    _sync_dir(rev.REVISIONS_DIR)


def _recover_locked():
    import runtime_publication
    from singbox.runtime_client import enabled as runtime_enabled
    if runtime_enabled() and rev.JOURNAL_PATH.exists():
        raise manager.SingboxConfigError("recover the legacy revision journal before enabling runtime mode")
    recovered = runtime_publication.recover_locked()
    if not rev.JOURNAL_PATH.exists():
        return bool(recovered)
    try:
        journal = _json_read(rev.JOURNAL_PATH)
        if journal.get("version") != 1:
            raise ValueError("invalid recovery version")
        if journal["phase"] == "committed":
            # The commit marker follows durable files, metadata and successful reload.
            state = _json_read(rev.STATE_PATH)
            if (digest(_observed(journal["revisionId"])) != journal["bundleHash"]
                    or state.get("bundleHash") != journal["bundleHash"]
                    or state.get("currentRevisionId") != journal["revisionId"]
                    or digest(_json_read(rev.CURRENT_BUNDLE_PATH)) != journal["bundleHash"]):
                raise ValueError("committed files changed")
            _remove_journal()
            return True
        if journal.get("phase") != "prepared" or journal.get("version") != 1:
            raise ValueError("invalid recovery phase")
        before = journal["before"]
        if set(before) != set(_paths()) or journal.get("beforeHash") != digest(before):
            raise ValueError("invalid recovery record")
        for name, path in _paths().items():
            _restore(path, before[name])
        for name, path in _paths().items():
            if _capture(path) != before[name]:
                raise ValueError("recovery readback mismatch")
        # With no previous config, runtime rollback cannot be proved; retain the
        # journal and refuse service startup/mutation pending operator recovery.
        if before["config"] is None or not rev.reload_singbox():
            raise ValueError("previous runtime could not be restored")
        _remove_journal()
        return True
    except Exception as error:
        raise manager.SingboxConfigError("revision recovery required; journal retained") from error


def recover_pending_revision():
    with manager._config_lock():
        return _recover_locked()


def get_revision_state():
    with manager._config_lock():
        state = copy.deepcopy(rev._read_state())
        import runtime_publication
        from singbox.runtime_client import enabled as runtime_enabled
        pending = rev.JOURNAL_PATH.exists() or runtime_publication.paths()[0].exists()
        try:
            observed_hash = digest(_observed(state.get("currentRevisionId")))
        except (OSError, ValueError):
            observed_hash = None
        verified = (not pending and state.get("bundleHash") is not None
                    and observed_hash == state.get("bundleHash"))
        state.update(nodeId=rev.config.node.id, configPath=str(rev.CONFIG_PATH),
                     singboxRunning=rev.is_singbox_running(), observedBundleHash=observed_hash,
                     filesVerified=verified, recoveryRequired=pending,
                     verificationScope="files-and-reload")
        if runtime_enabled():
            state["verificationScope"] = "files-and-runtime"
            try:
                state["runtime"] = runtime_publication.verify_current()
                state["runtimeVerified"] = True
            except manager.SingboxConfigError:
                state["runtimeVerified"] = False
                state["status"] = "drifted"
        if pending:
            state["status"] = "recovery-required"
        elif state.get("bundleHash") and not verified:
            state["status"] = "drifted"
        return state


def _validate_config(data):
    rev.REVISIONS_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, name = tempfile.mkstemp(prefix="check.", suffix=".json", dir=rev.REVISIONS_DIR)
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        valid, error = rev.check_config(path)
        if not valid:
            raise manager.SingboxConfigError("sing-box config validation failed: " + str(error))
    finally:
        path.unlink(missing_ok=True)


def _commit(target, state, action):
    _validate_config(target["config"])
    from singbox.runtime_client import enabled as runtime_enabled
    if runtime_enabled():
        return _commit_runtime(target, state, action)
    before = {name: _capture(path) for name, path in _paths().items()}
    journal = {"version": 1, "phase": "prepared", "before": before,
               "beforeHash": digest(before),
               "revisionId": target["revisionId"], "bundleHash": digest(target)}
    _json_write(rev.JOURNAL_PATH, journal)
    try:
        old_config = before["config"]
        _atomic(rev.CONFIG_PATH, (rev._canonical_json(target["config"]) + "\n").encode(),
                old_config["mode"] if old_config else 0o600,
                old_config.get("owner") if old_config else None)
        manager._write_registry(target["registry"])
        _sync_dir(manager.REGISTRY_PATH.parent)
        if digest(_observed(target["revisionId"])) != digest(target):
            raise manager.SingboxConfigError("revision file readback mismatch")
        if not rev.reload_singbox():
            raise manager.SingboxConfigError("sing-box reload failed")
        if before["config"] is not None and before["registry"] is not None:
            previous = bundle(state.get("currentRevisionId"),
                json.loads(base64.b64decode(before["config"]["bytes"])),
                json.loads(base64.b64decode(before["registry"]["bytes"])))
            if previous["revisionId"] is None or digest(previous) != state.get("bundleHash"):
                # Ordinary account mutations can legitimately change a published
                # bundle. Preserve those bytes under a distinct snapshot identity.
                previous["revisionId"] = "local-" + digest(previous)[:32]
            _json_write(rev.LAST_GOOD_BUNDLE_PATH, previous)
            _json_write(rev.LAST_GOOD_PATH, previous["config"])
            state.update(lastGoodRevisionId=previous["revisionId"], lastGoodHash=digest(previous))
        _json_write(rev.CURRENT_BUNDLE_PATH, target)
        _json_write(rev.CURRENT_PATH, target["config"])
        full_hash = digest(target)
        state.update(version=2, currentRevisionId=target["revisionId"], currentHash=full_hash,
                     bundleHash=full_hash, configHash=digest(target["config"]),
                     registryHash=digest(target["registry"]), status=action,
                     appliedAt=datetime.now(timezone.utc).isoformat(), lastError=None)
        state.setdefault("revisionDigests", {})[target["revisionId"]] = full_hash
        rev._append_history(state, target["revisionId"], full_hash, action, None)
        _json_write(rev.STATE_PATH, state)
        if _json_read(rev.STATE_PATH) != state or digest(_observed(target["revisionId"])) != full_hash:
            raise manager.SingboxConfigError("revision commit readback mismatch")
        journal["phase"] = "committed"
        _json_write(rev.JOURNAL_PATH, journal)
    except Exception as error:
        # Restore *all* snapshots and metadata as well as both active files.
        try:
            _recover_locked()
        except manager.SingboxConfigError:
            raise manager.SingboxConfigError("revision failed; recovery required; journal retained") from error
        raise manager.SingboxConfigError("revision failed; previous bundle restored: " + str(error)) from error
    _remove_journal()
    return {"success": True, "revisionId": target["revisionId"], "replayed": False,
            "filesVerified": True, "verificationScope": "files-and-reload", **state}


def _commit_runtime(target, state, action):
    import runtime_publication as publication
    current_config = _json_read(rev.CONFIG_PATH) if rev.CONFIG_PATH.exists() else {}
    targets = {rev.CONFIG_PATH: publication.canonical(target["config"]),
               manager.REGISTRY_PATH: publication.canonical(target["registry"])}
    if rev.CONFIG_PATH.exists() and manager.REGISTRY_PATH.exists():
        previous = bundle(state.get("currentRevisionId"), current_config, manager.read_registry())
        if previous["revisionId"] is None or digest(previous) != state.get("bundleHash"):
            previous["revisionId"] = "local-" + digest(previous)[:32]
        targets[rev.LAST_GOOD_BUNDLE_PATH] = publication.canonical(previous)
        targets[rev.LAST_GOOD_PATH] = publication.canonical(previous["config"])
        state.update(lastGoodRevisionId=previous["revisionId"], lastGoodHash=digest(previous))
    full_hash = digest(target)
    prepared = publication.prepare(current_config, target["config"])
    state.update(version=2, currentRevisionId=target["revisionId"], currentHash=full_hash,
                 bundleHash=full_hash, configHash=digest(target["config"]),
                 registryHash=digest(target["registry"]), status=action,
                 runtimeContentHash=prepared["targetHash"], verificationScope="files-and-runtime",
                 appliedAt=datetime.now(timezone.utc).isoformat(), lastError=None)
    state.setdefault("revisionDigests", {})[target["revisionId"]] = full_hash
    rev._append_history(state, target["revisionId"], full_hash, action, None)
    targets.update({rev.CURRENT_BUNDLE_PATH: publication.canonical(target),
                    rev.CURRENT_PATH: publication.canonical(target["config"]),
                    rev.STATE_PATH: publication.canonical(state)})
    receipt = publication.commit_files(target["config"], current_config, targets, prepared)
    return {**state, "success": True, "revisionId": target["revisionId"], "replayed": False,
            "filesVerified": True, "verificationScope": "files-and-runtime", "runtime": receipt}


def apply_desired_revision(desired_config, desired_registry, signature, revision_id,
                           allow_user_deletion=False):
    if not revision_id:
        raise manager.SingboxConfigError("revision_id is required")
    payload = {"config": desired_config, "registry": desired_registry}
    # Retain the existing wire signature for compatible publishers. The receipt
    # digest additionally binds normalized registry, revision and local node ID.
    if not rev.verify_signature(payload, signature):
        rev._archive_rejected(payload, "signature-mismatch")
        raise manager.SingboxConfigError("revision signature verification failed")
    registry, error = rev._validate_registry_payload(desired_registry)
    problem = rev._find_node_target_mismatch(desired_config, desired_registry)
    conflicts = rev._find_port_conflicts(desired_config)
    if error or problem or conflicts:
        reason = ("registry-invalid: " + error if error else "node-target-mismatch: " + problem
                  if problem else "port-conflict: " + "; ".join(conflicts))
        rev._archive_rejected(payload, reason)
        raise manager.SingboxConfigError(reason.replace("port-conflict", "port conflict").replace("node-target-mismatch", "node target mismatch"))
    target = bundle(revision_id, desired_config, registry)
    with manager._config_lock():
        _recover_locked()
        state = rev._read_state()
        known_hash = state.get("revisionDigests", {}).get(revision_id)
        if known_hash and known_hash != digest(target):
            raise manager.SingboxConfigError("revision content conflict")
        if known_hash and state.get("currentRevisionId") != revision_id:
            raise manager.SingboxConfigError("stale revision refused; use explicit rollback")
        if state.get("currentRevisionId") == revision_id:
            if state.get("bundleHash") != digest(target):
                raise manager.SingboxConfigError("revision content conflict or legacy receipt requires new revision")
            if digest(_observed(revision_id)) != digest(target):
                raise manager.SingboxConfigError("revision drift detected; cannot replay success")
            from singbox.runtime_client import enabled as runtime_enabled
            if runtime_enabled():
                import runtime_publication
                runtime_publication.verify_current()
            return {"success": True, "revisionId": revision_id, "replayed": True,
                    "filesVerified": True, "verificationScope": "files-and-reload", **state}
        current = rev.read_config() if rev.CONFIG_PATH.exists() else {}
        current_registry = manager.read_registry()
        removed = manager._discover_user_ids(current, current_registry) - manager._discover_user_ids(desired_config, registry)
        if removed and not allow_user_deletion:
            rev._archive_rejected(payload, "user-shrink-blocked")
            raise manager.SingboxConfigError("revision would remove existing users; set allowUserDeletion=true to override")
        try:
            return _commit(target, state, "applied")
        except manager.SingboxConfigError as error:
            rev._archive_rejected(payload, "reload-failed" if "reload failed" in str(error)
                                  else "check-failed" if "validation failed" in str(error) else "apply-failed")
            raise


def rollback_to_last_known_good():
    with manager._config_lock():
        _recover_locked()
        if not rev.LAST_GOOD_BUNDLE_PATH.exists():
            raise manager.SingboxConfigError("no complete last_known_good bundle available; legacy config-only rollback refused")
        try:
            target = _json_read(rev.LAST_GOOD_BUNDLE_PATH)
            state = rev._read_state()
            if (target.get("nodeId") != str(rev.config.node.id) or
                    digest(target) != state.get("lastGoodHash")):
                raise ValueError("snapshot mismatch")
            return _commit(target, state, "rolled-back")
        except Exception as error:
            raise manager.SingboxConfigError("rollback failed; " + str(error)) from error
