"""Durable single-process runtime publication; callers hold manager's config lock.

Unknown outcomes retain the journal. Recovery fences delayed old-revision PUTs
before restoring files. It never issues an unfenced runtime rollback or HUP.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from singbox import manager
from singbox.runtime_client import RuntimeClient, RuntimeUnavailable, RuntimeRejected, enabled, check_mode

class RuntimeRecoveryRequired(manager.SingboxConfigError):
    pass

related_targets = ContextVar("runtime_related_targets", default=None)

def paths():
    root = Path(os.environ.get("NODE_MANAGER_RUNTIME_STATE_DIR", str(manager.REGISTRY_PATH.parent / "runtime")))
    return root / "transaction.json", root / "current.json"

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def sync_dir(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

def atomic(path, data, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if owner and hasattr(os, "chown"):
            os.chown(temporary, *owner)
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)

def capture(path):
    path = Path(path)
    if not path.exists():
        return None
    stat = path.stat()
    return {"data": base64.b64encode(path.read_bytes()).decode("ascii"),
            "mode": stat.st_mode & 0o777, "owner": [stat.st_uid, stat.st_gid]}

def restore(path, record):
    path = Path(path)
    if record is None:
        path.unlink(missing_ok=True)
        if path.parent.exists():
            sync_dir(path.parent)
    else:
        atomic(path, base64.b64decode(record["data"], validate=True), record["mode"], record.get("owner"))

def assert_no_pending():
    if paths()[0].exists():
        raise RuntimeRecoveryRequired("runtime recovery required; transaction journal retained")

@contextmanager
def related_transaction():
    token = related_targets.set({})
    try:
        yield
    finally:
        related_targets.reset(token)

def stage_related(path, value):
    targets = related_targets.get()
    if targets is None:
        raise manager.SingboxConfigError("related runtime transaction is missing")
    targets[Path(path)] = canonical(value)

def prepare(previous, desired):
    check_mode()
    client = RuntimeClient()
    old = client.preview(previous)
    target = client.preview(desired)
    if old["runtime"] != target["runtime"] or old["runtime"]["contentHash"] != old["contentHash"]:
        raise manager.SingboxConfigError("runtime configuration drift; publication refused")
    if not target["supported"]:
        raise manager.SingboxConfigError("unsupported runtime topology change; publication refused")
    return {"socket": check_mode(), "expected": old["runtime"], "previousHash": old["contentHash"], "targetHash": target["contentHash"]}

def resolve(prepared):
    """Prove applied, or fence every delayed PUT before proving unchanged."""
    if prepared.get("socket") != check_mode():
        raise RuntimeRecoveryRequired("runtime socket changed during pending publication")
    client = RuntimeClient()
    for _ in range(3):
        status = client.status()
        if status["contentHash"] == prepared["targetHash"]:
            return "applied", status
        if status["contentHash"] != prepared["previousHash"]:
            raise RuntimeRecoveryRequired("runtime state conflicts with pending publication; journal retained")
        try:
            fenced = client.fence(status)
        except RuntimeRejected as error:
            if error.status == 409:
                continue
            raise
        if (fenced["instanceId"] != status["instanceId"] or fenced["contentHash"] != prepared["previousHash"]
                or fenced["revision"] <= status["revision"]):
            raise RuntimeRecoveryRequired("runtime recovery fence could not be verified")
        return "unchanged", fenced
    raise RuntimeRecoveryRequired("runtime changed during recovery; journal retained")

def publish(data, prepared):
    client = RuntimeClient()
    try:
        receipt = client.apply(data, prepared["expected"])
        if receipt["contentHash"] == prepared["targetHash"] and receipt["instanceId"] == prepared["expected"]["instanceId"]:
            observed = client.status()
            if (observed["instanceId"] == receipt["instanceId"] and observed["contentHash"] == prepared["targetHash"]
                    and observed["revision"] >= receipt["revision"]):
                return "applied", receipt
    except (RuntimeUnavailable, RuntimeRejected):
        pass
    return resolve(prepared)

def _remove_journal():
    journal, _ = paths()
    journal.unlink(missing_ok=True)
    try:
        sync_dir(journal.parent)
    except OSError:
        # All outcome files and the receipt were already flushed. If a crash
        # resurrects this WAL, recovery is idempotent. Never report a failed
        # publication after committing and removing its recovery record.
        manager.logger.warning("runtime journal deletion sync failed; committed outcome retained")

def _write_records(records):
    for path, record in records.items():
        restore(path, record)
    for path, record in records.items():
        observed = capture(path)
        if record is None:
            valid = observed is None
        else:
            valid = observed is not None and observed["data"] == record["data"]
            if os.name != "nt" and valid:
                valid = observed["mode"] == record["mode"] and (record.get("owner") is None or observed["owner"] == record["owner"])
        if not valid:
            raise OSError("runtime transaction file readback mismatch")

def read_aliases():
    if not paths()[1].exists():
        return {}
    value = json.loads(paths()[1].read_text(encoding="utf-8")).get("authAliases", {})
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise manager.SingboxConfigError("runtime identity history is invalid")
    return value

def merge_aliases(data, registry, aliases):
    import runtime_history as history
    previous = aliases
    aliases = {}
    for user_id in manager._discover_user_ids(data, registry):
        for name in manager._user_auth_names(registry, user_id):
            if name in previous and previous[name] != user_id:
                raise manager.SingboxConfigError("runtime authentication name belongs to another historical user")
            aliases[name] = user_id
    stored = history.owners(aliases)
    if any(aliases[name] != owner for name,owner in stored.items()):
        raise manager.SingboxConfigError("runtime authentication name belongs to another historical user")
    return aliases

def _receipt(config, receipt, aliases=None, archived_versions=None):
    import runtime_history as history
    previous = read_aliases()
    # Import r2/r3 identity history before replacing the hot receipt. Never
    # discard ownership proof merely because its user is no longer active.
    history.bind_owners(previous)
    if aliases is None:
        aliases = merge_aliases(config, manager.read_registry(), previous)
    history.bind_owners(aliases)
    history.versions(archived_versions or {})
    atomic(paths()[1], canonical({"version": 1, "config": config, "runtime": receipt, "authAliases": aliases}))

def commit_files(config, previous_config, targets, prepared=None):
    assert_no_pending()
    prepared = prepare(previous_config, config) if prepared is None else prepared
    targets = {Path(path): data for path, data in targets.items()}
    targets.update(related_targets.get() or {})
    desired_registry = json.loads(targets.get(manager.REGISTRY_PATH, canonical(manager.read_registry())))
    active_ids = manager._discover_user_ids(config, desired_registry)
    archived_versions = {uid:version for uid,version in desired_registry.get("runtimeUserVersions",{}).items() if uid not in active_ids}
    if archived_versions:
        desired_registry["runtimeUserVersions"] = {uid:version for uid,version in desired_registry["runtimeUserVersions"].items() if uid in active_ids}
        targets[manager.REGISTRY_PATH] = canonical(desired_registry)
    before = {str(path.resolve()): capture(path) for path in targets}
    after = {}
    for path, data in targets.items():
        key = str(path.resolve())
        old = before[key]
        after[key] = {"data": base64.b64encode(data).decode("ascii"),
                      "mode": old["mode"] if old else 0o600,
                      "owner": old["owner"] if old else None}
    old_receipt = capture(paths()[1])
    aliases = merge_aliases(previous_config, manager.read_registry(), read_aliases())
    aliases = merge_aliases(config, desired_registry, aliases)
    journal = {"version": 1, "prepared": prepared, "config": config,
               "before": before, "after": after, "oldReceipt": old_receipt, "authAliases": aliases, "archivedVersions":archived_versions}
    journal["integrity"] = digest(journal)
    try:
        atomic(paths()[0], canonical(journal))
    except Exception as error:
        # A directory fsync may fail after replace made the WAL visible.
        if paths()[0].exists():
            raise RuntimeRecoveryRequired("runtime journal persistence uncertain; recovery required") from error
        raise
    try:
        _write_records(after)
        outcome, receipt = publish(config, prepared)
        if outcome == "unchanged":
            _write_records(before)
            restore(paths()[1], old_receipt)
            _remove_journal()
            raise manager.SingboxConfigError("runtime update rejected; previous files restored")
        _receipt(config, receipt, aliases, archived_versions)
        _remove_journal()
        return receipt
    except manager.SingboxConfigError as error:
        if paths()[0].exists():
            raise RuntimeRecoveryRequired("runtime recovery required; transaction journal retained") from error
        raise
    except Exception as error:
        try:
            outcome, recovered_receipt = recover_locked(return_receipt=True)
        except Exception:
            raise RuntimeRecoveryRequired("runtime publication uncertain; recovery required; journal retained") from error
        if outcome == "applied":
            # Recovery already verified and committed this receipt. A second
            # socket query could fail after success and make replication undo
            # its traffic file despite the committed config/registry bundle.
            return recovered_receipt
        raise manager.SingboxConfigError("runtime publication failed; previous files restored") from error

def recover_locked(*, return_receipt=False):
    journal_path, _ = paths()
    if not journal_path.exists():
        return (False, None) if return_receipt else False
    if not enabled():
        raise RuntimeRecoveryRequired("enable the recorded runtime mode before recovering its journal")
    try:
        check_mode()
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        integrity = journal.pop("integrity")
        if journal.get("version") != 1 or digest(journal) != integrity:
            raise ValueError("invalid runtime journal")
        outcome, receipt = resolve(journal["prepared"])
        if outcome == "applied":
            _write_records(journal["after"])
            _receipt(journal["config"], receipt, journal["authAliases"],journal.get("archivedVersions",{}))
        else:
            _write_records(journal["before"])
            restore(paths()[1], journal["oldReceipt"])
        _remove_journal()
        return (outcome, receipt) if return_receipt else outcome
    except Exception as error:
        raise RuntimeRecoveryRequired("runtime recovery required; journal retained") from error

def commit(config, registry, previous_config):
    return commit_files(config, previous_config, {
        manager.CONFIG_PATH: canonical(config), manager.REGISTRY_PATH: canonical(registry)})

def verify_current():
    check_mode()
    preview = RuntimeClient().preview(manager.read_config())
    if preview["runtime"]["contentHash"] != preview["contentHash"]:
        raise manager.SingboxConfigError("runtime configuration drift; reconciliation required")
    return preview["runtime"]

def initialize_locked():
    recover_locked()
    if enabled():
        for inbound in manager.read_config().get("inbounds", []):
            if inbound.get("type") == "socks" and inbound.get("tag") == manager.config.singbox.socks_tag and inbound.get("require_auth") is not True:
                raise manager.SingboxConfigError("set require_auth:true on the managed SOCKS inbound before enabling runtime mode")
        receipt = verify_current()
        _receipt(manager.read_config(), receipt)

def apply_disk():
    assert_no_pending()
    data = manager.read_config()
    previous = data
    if paths()[1].exists():
        previous = json.loads(paths()[1].read_text(encoding="utf-8"))["config"]
    observed = RuntimeClient().preview(data)
    if observed["contentHash"] == observed["runtime"]["contentHash"]:
        _receipt(data, observed["runtime"])
        return observed["runtime"]
    return commit(data, manager.read_registry(), previous)
