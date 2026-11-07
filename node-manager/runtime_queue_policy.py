"""Durable pending-intent aliases and bounded single-writer scheduling.

No payloads/credentials are persisted here. Same-key replay is never forgotten;
only equivalent *unfinished* access commands may share an existing task.
"""
from __future__ import annotations

from dataclasses import dataclass
import time


@dataclass(frozen=True)
class Policy:
    priority: int = 1
    kind: str = 'interactive'
    scope: str | None = None
    target: int | None = None


def classify(key, payload, keys):
    scope = next(iter(keys)) if len(keys) == 1 else None
    commands = payload.get('commands', []) if isinstance(payload, dict) else []
    if commands and all(isinstance(c, dict) for c in commands):
        if all(c.get('action') == 'delete' or (c.get('action') == 'access' and c.get('enabled') is False)
               for c in commands):
            return Policy(0, 'security', scope)
        if len(commands) == 1 and commands[0].get('action') == 'access' and scope:
            c = commands[0]
            if c.get('userId') == scope and type(c.get('enabled')) is bool:
                # Caller-supplied versions remain part of the fingerprint.
                maintenance = str(key or '').startswith('task:acceleration-access:')
                return Policy(2 if maintenance else 1, 'access', scope, int(c['enabled']))
    if str(key or '').startswith('legacy:traffic-cycle:'):
        return Policy(2, 'maintenance', scope)
    return Policy(scope=scope)


def access_policy(key, payload, keys):
    result = classify(key, payload, keys)
    commands = payload.get('commands', []) if isinstance(payload, dict) else []
    # Disables have security priority but still support pending-intent aliases.
    if len(commands) == 1 and isinstance(commands[0], dict) and commands[0].get('action') == 'access':
        c = commands[0]
        if result.scope and c.get('userId') == result.scope and type(c.get('enabled')) is bool:
            return Policy(result.priority, 'access', result.scope, int(c['enabled']))
    return result


def error_category(error):
    if error is None:
        return None
    name = type(error).__name__
    if name == 'RuntimeRejected':
        status = getattr(error, 'status', None)
        return 'RUNTIME_HTTP_' + str(status) if status in (400, 401, 403, 404, 409, 422, 500, 503) else 'RUNTIME_REJECTED'
    if name in ('RuntimeUnavailable', 'RuntimeRecoveryRequired', 'TimeoutError', 'PermissionError', 'OSError'):
        return {'RuntimeUnavailable':'RUNTIME_UNAVAILABLE', 'RuntimeRecoveryRequired':'PUBLICATION_UNCERTAIN',
                'TimeoutError':'TIMEOUT', 'PermissionError':'FILESYSTEM_PERMISSION', 'OSError':'FILESYSTEM_ERROR'}[name]
    message = str(error)
    for prefix, code in [('runtime configuration drift', 'RUNTIME_DRIFT'),
                         ('unsupported runtime topology', 'UNSUPPORTED_TOPOLOGY'),
                         ('runtime update rejected; previous files restored', 'RUNTIME_REJECTED_RESTORED'),
                         ('runtime publication failed; previous files restored', 'PUBLICATION_FAILED_RESTORED'),
                         ('PROVISIONING_', 'LISTENER_NOT_READY'),
                         ('user version changed;', 'USER_VERSION_CONFLICT')]:
        if message.startswith(prefix):
            return code
    if name == 'SingboxConfigError':
        from runtime_metrics import rejection_category
        category = rejection_category(error)
        return 'MUTATION_REJECTED' if category == 'POLICY_REJECTED' else category
    return 'INTERNAL_ERROR'


class DurablePolicy:
    def __init__(self, db):
        self.db = db
        db.execute('''CREATE TABLE IF NOT EXISTS task_request_alias (
            request_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, task_id TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS task_diagnostic (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT UNIQUE NOT NULL,
            priority INTEGER NOT NULL, kind TEXT NOT NULL, scope TEXT, target INTEGER,
            queued_at REAL NOT NULL, started_at REAL, finished_at REAL, error_category TEXT)''')
        db.execute('CREATE INDEX IF NOT EXISTS task_diagnostic_scope ON task_diagnostic(scope,sequence)')
        columns = {row[1] for row in db.execute('PRAGMA table_info(task_diagnostic)')}
        for column in ('failed_phase', 'phase_times'):
            if column not in columns:
                db.execute('ALTER TABLE task_diagnostic ADD COLUMN ' + column + ' TEXT')
        db.commit()

    def alias(self, key):
        return self.db.execute('SELECT task_id,fingerprint FROM task_request_alias WHERE request_key=?', (key,)).fetchone()

    def equivalent(self, info, fingerprint):
        if info.kind != 'access' or not info.scope:
            return None
        # Inspect the newest generation of ANY command for this user. Never
        # merge true -> false -> true, or bypass intervening credential/routes.
        row = self.db.execute('''SELECT d.task_id,d.kind,d.target,t.state,t.fingerprint,d.sequence
            FROM task_diagnostic d LEFT JOIN tasks t ON t.id=d.task_id
            WHERE d.scope=? ORDER BY d.sequence DESC LIMIT 1''', (info.scope,)).fetchone()
        if row and row[1] == 'access' and row[2] == info.target and row[3] in ('QUEUED', 'RUNNING') and row[4] == fingerprint:
            # A multi-user/unknown-scope operation may also change this user.
            # Its presence is a barrier even when it has a different API key.
            barrier = self.db.execute('SELECT 1 FROM task_diagnostic WHERE scope IS NULL AND sequence>? LIMIT 1',
                                      (row[5],)).fetchone()
            if barrier: return None
            return row[0]
        return None

    def record(self, task_id, info, created):
        self.db.execute('''INSERT INTO task_diagnostic
            (task_id,priority,kind,scope,target,queued_at) VALUES (?,?,?,?,?,?)''',
            (task_id, info.priority, info.kind, info.scope, info.target, created))

    def materialize_terminal_aliases(self, task_id):
        """Mirror terminal receipts for older readers before releasing waiters.

        Rolling back still requires draining/reconciling outstanding work. An old
        writer can then replay every accepted request key without executing it.
        """
        import hashlib
        rows = self.db.execute('''SELECT a.request_key,a.fingerprint,t.state,t.created,t.updated,
                t.batch,t.result,t.reason,t.units FROM task_request_alias a JOIN tasks t ON t.id=a.task_id
                WHERE t.id=? AND t.state IN ('SUCCEEDED','FAILED','CANCELLED','NOT_APPLIED')''',(task_id,)).fetchall()
        for row in rows:
            previous = self.db.execute('SELECT fingerprint,state FROM task_archive WHERE request_key=?',(row[0],)).fetchone()
            if previous:
                if previous[0]!=row[1] or previous[1]!=row[2]:
                    raise RuntimeError('terminal alias receipt conflict')
                continue
            alias_id=hashlib.sha256(('runtime-alias:'+row[0]).encode()).hexdigest()[:32]
            self.db.execute('INSERT INTO task_archive VALUES (?,?,?,?,?,?,?,?,?,?)',(alias_id,*tuple(row)))

    def detail(self, task_id):
        row = self.db.execute('''SELECT priority,queued_at,started_at,finished_at,error_category,failed_phase,phase_times
            FROM task_diagnostic WHERE task_id=?''', (task_id,)).fetchone()
        if not row:
            return {}
        priority, queued, started, finished, error, failed_phase, phase_times = row
        import json
        return {'queueClass': ('security', 'interactive', 'maintenance')[priority],
                'queueWaitMs': round(max(0, (started or finished or time.time()) - queued) * 1000, 2),
                'executionMs': None if started is None else round(max(0, (finished or time.time()) - started) * 1000, 2),
                'errorCategory': error, 'failedPhase': failed_phase,
                'phaseTimesMs': json.loads(phase_times) if phase_times else {}}


def select_batch(pending, batch_size, maintenance_batch_size, force_maintenance=False):
    """Reorder independent users only; unscoped jobs form global FIFO barriers."""
    if not pending:
        return []
    pending = list(pending)
    # Required predecessors inherit urgency, avoiding a security revoke being
    # starved behind its own earlier maintenance command. Never reverse them.
    effective, urgency, global_urgency = {}, {}, 2
    for item in reversed(pending):
        inherited = min([urgency.get(key, 2) for key in item.keys] or list(urgency.values()) or [2])
        priority = min(item.priority, inherited, global_urgency)
        effective[item.task_id] = priority
        if not item.keys: global_urgency = priority
        for key in item.keys: urgency[key] = priority
    seen = set()
    eligible = []
    for index, item in enumerate(pending):
        if not item.keys:
            if index == 0:
                # Legacy unknown scope must retain the original prefix order.
                eligible = list(pending)
            break
        if not seen.intersection(item.keys):
            eligible.append(item)
        seen.update(item.keys)
    if not eligible:
        return []
    if not pending[0].keys:
        priority = effective[pending[0].task_id]
    else:
        priority = min(effective[i.task_id] for i in eligible)
        if priority != 0 and force_maintenance and any(effective[i.task_id] == 2 for i in eligible):
            priority = 2
    if not pending[0].keys:
        candidates = []
        for item in eligible:
            if item.keys or effective[item.task_id] != priority: break
            candidates.append(item)
    else:
        candidates = [i for i in eligible if effective[i.task_id] == priority]
    selected, units, size, keys = [], 0, 0, set()
    for item in candidates:
        if selected and (item.isolated or selected[0].isolated or keys.intersection(item.keys)
                         or units + item.units > batch_size or size + item.size > 1 << 20
                         or (priority == 2 and len(selected) >= maintenance_batch_size)):
            break
        selected.append(item); units += item.units; size += item.size; keys.update(item.keys)
        if item.isolated:
            break
    return selected
