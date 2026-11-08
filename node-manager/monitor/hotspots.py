"""Read-only, cross-core diagnostics. Never feeds accounting or enforcement.

Only established sessions present in consecutive samples have rate estimates.
This is deliberately separate from durable quota counters: missing, restarted
or draining cores must not change a customer's balance or access policy.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests
from monitor import capacity_counters

INTERVAL = 60.0
MAX_SOURCES = 16
MAX_BODY = 16 << 20
UNIT = re.compile(r"(?:^|/)system\.slice/(?:sing-box(?:-shared)?|niusu-vless-gen-[0-9a-f]{12})\.service(?:\n|$)")
USER = re.compile(r"(?:primary-\d+|backup-\d+|shared-[a-z0-9-]{1,100})\Z")


@dataclass
class Core:
    pid: int
    start: int
    port: int
    secret: str = field(repr=False)
    inbounds: list = field(default_factory=list)
    resources: dict = field(default_factory=dict, repr=False)

    @property
    def key(self):
        return f"{self.pid}:{self.start}:{self.port}"


def identity(pid, proc=Path('/proc')):
    raw = (proc / str(pid) / 'stat').read_text()
    return int(raw.rsplit(')', 1)[1].split()[19])


def discover(proc=Path('/proc')):
    """Trust local service ownership; never accept URLs from HTTP parameters."""
    cores, errors, ports = [], 0, set()
    for base in proc.iterdir():
        if not base.name.isdigit():
            continue
        owned = False
        try:
            if not (base / 'comm').read_text().startswith('sing-box'):
                continue
            if not UNIT.search((base / 'cgroup').read_text()):
                continue
            owned = True
            pid = int(base.name)
            start = identity(pid, proc)
            args = (base / 'cmdline').read_bytes().decode().split('\0')
            paths = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in ('-c', '--config')]
            if len(paths) != 1:
                raise ValueError('unsupported_config_layout')
            path = Path(paths[0])
            if not path.is_absolute() or path.stat().st_size > MAX_BODY:
                raise ValueError('invalid_config')
            cfg = json.loads(path.read_text())
            api = cfg.get('experimental', {}).get('clash_api', {})
            match = re.fullmatch(r'127\.0\.0\.1:(\d{1,5})', api.get('external_controller', ''))
            if not match or not 1 <= int(match[1]) <= 65535:
                raise ValueError('non_loopback_controller')
            port = int(match[1])
            if port in ports or len(cores) >= MAX_SOURCES:
                raise ValueError('ambiguous_or_excess_sources')
            inbounds = [{'protocol': row.get('type'), 'port': row.get('listen_port')}
                        for row in cfg.get('inbounds', []) if row.get('type') in ('vless', 'vmess', 'socks')]
            resources = {}
            for row in cfg.get('outbounds', []):
                tag = row.get('tag', '')
                if not tag.startswith('node-manager-out:'):
                    continue
                uid = tag[len('node-manager-out:'):]
                if USER.fullmatch(uid):
                    try:
                        resources[uid] = str(ipaddress.ip_address(row.get('server')))
                    except ValueError:
                        pass
            if identity(pid, proc) != start:
                raise ValueError('core_changed')
            secret = api.get('secret', '')
            if not isinstance(secret, str):
                raise ValueError('invalid_controller')
            cores.append(Core(pid, start, port, secret, inbounds, resources))
            ports.add(port)
        except (OSError, ValueError, TypeError, AttributeError, KeyError, IndexError):
            errors += int(owned)
    return cores, errors


def fetch(core):
    if identity(core.pid) != core.start:
        raise ValueError('core_changed')
    headers = {'Authorization': f'Bearer {core.secret}'} if core.secret else {}
    started = time.monotonic()
    with requests.get(f'http://127.0.0.1:{core.port}/connections', headers=headers,
                      timeout=(1, 2), stream=True, allow_redirects=False,
                      proxies={'http': '', 'https': ''}) as response:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError('unexpected_response')
        body = bytearray()
        for part in response.iter_content(65536):
            body.extend(part)
            if len(body) > MAX_BODY or time.monotonic() - started > 3:
                raise ValueError('snapshot_limit')
    value = json.loads(body)
    if identity(core.pid) != core.start:
        raise ValueError('core_changed')
    return value


def project(snapshot):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('connections'), list):
        raise ValueError('invalid_snapshot')
    rows = {}
    for row in snapshot['connections']:
        if not isinstance(row, dict):
            raise ValueError('invalid_connection')
        cid = row.get('id')
        if not isinstance(cid, str) or not cid or cid in rows:
            raise ValueError('ambiguous_connection')
        up, down = row.get('upload'), row.get('download')
        if any(type(v) is not int or not 0 <= v < 2**63 for v in (up, down)):
            raise ValueError('invalid_counters')
        uid = None
        for tag in row.get('chains') or []:
            if isinstance(tag, str) and tag.startswith('node-manager-out:'):
                candidate = tag[len('node-manager-out:'):]
                if USER.fullmatch(candidate):
                    if uid is not None and uid != candidate:
                        raise ValueError('ambiguous_user')
                    uid = candidate
        rows[cid] = (uid, up, down)
    return rows


class Hotspots:
    def __init__(self):
        self.lock = threading.Lock()
        self.sampling = threading.Lock()
        self.previous = {}
        self.previous_kernel = None
        self.previous_kernel_time = None
        self.value = {'sampleTime': None, 'complete': False, 'sources': [], 'topDownload': [],
                      'topUpload': [], 'reason': 'no_sample'}

    def sample(self, discover_fn=discover, fetch_fn=fetch, clock=time.monotonic,
               kernel_fn=capacity_counters.read):
        # Never queue or overlap an expensive scan, even during concurrent API reads.
        if not self.sampling.acquire(blocking=False):
            return False
        try:
            kernel_at = clock()
            kernel = kernel_fn()
            kernel_result = capacity_counters.difference(kernel, self.previous_kernel)
            kernel_result['intervalSeconds'] = (kernel_at - self.previous_kernel_time
                                                if self.previous_kernel_time is not None else None)
            self.previous_kernel, self.previous_kernel_time = kernel, kernel_at
            sources, errors = discover_fn()
            next_previous, observed, users = {}, [], {}
            deadline = clock() + 12
            for core in sources:
                status = {'sourceId': core.key, 'pid': core.pid, 'inbounds': core.inbounds,
                          'available': False, 'ratesAvailable': False}
                try:
                    if clock() >= deadline:
                        raise ValueError('sample_budget')
                    rows = project(fetch_fn(core))
                    now = clock()
                    prior = self.previous.get(core.key)
                    next_previous[core.key] = (now, rows)
                    status.update(available=True, activeConnections=len(rows),
                                  attributedConnections=sum(r[0] is not None for r in rows.values()))
                    if prior is None or not 0 < now - prior[0] <= INTERVAL * 3:
                        status['reason'] = 'warming_up'
                    else:
                        dt = now - prior[0]
                        matched, resets, new = 0, 0, 0
                        sums = [0, 0]
                        for cid, (uid, up, down) in rows.items():
                            old = prior[1].get(cid)
                            if old is None:
                                new += 1
                                continue
                            if uid != old[0] or up < old[1] or down < old[2]:
                                resets += 1
                                continue
                            matched += 1
                            rates = ((up - old[1]) * 8 / dt / 1e6, (down - old[2]) * 8 / dt / 1e6)
                            sums = [a + b for a, b in zip(sums, rates)]
                            item = users.setdefault(uid, {'nodeUserId': uid, 'matchedConnections': 0,
                                                        'uploadMbps': 0.0, 'downloadMbps': 0.0})
                            item['matchedConnections'] += 1
                            item['uploadMbps'] += rates[0]
                            item['downloadMbps'] += rates[1]
                            if uid in core.resources:
                                resource = core.resources[uid]
                                existing = item.get('residentialIP')
                                if item.get('resourceIdentityConflict'):
                                    item['residentialIPs'] = sorted(set(item['residentialIPs']) | {resource})
                                elif existing and existing != resource:
                                    item.pop('residentialIP')
                                    item.update(resourceIdentityConflict=True,
                                                residentialIPs=sorted({existing, resource}))
                                else:
                                    item['residentialIP'] = resource
                        status.update(ratesAvailable=True, intervalSeconds=round(dt, 3),
                                      matchedConnections=matched, newConnectionsExcluded=new,
                                      closedConnectionsExcluded=len(prior[1].keys() - rows.keys()),
                                      counterResetsExcluded=resets, uploadMbps=round(sums[0], 3),
                                      downloadMbps=round(sums[1], 3))
                except (OSError, ValueError, TypeError, KeyError, requests.RequestException):
                    status['reason'] = 'core_snapshot_unavailable'
                observed.append(status)
            # Removed or failed processes lose their baseline; recovery warms up.
            self.previous = next_previous
            for item in users.values():
                for field_name in ('uploadMbps', 'downloadMbps'):
                    item[field_name] = round(item[field_name], 3)
            complete = bool(observed) and errors == 0 and all(r['ratesAvailable'] for r in observed)
            value = {'sampleTime': datetime.now(timezone.utc).isoformat(),
                     'complete': complete, 'discoveryErrors': errors, 'sources': observed,
                     'kernel': kernel_result,
                     'measurementBasis': 'matched_live_sessions_only_not_billing',
                     'reason': None if complete else 'partial_or_warming_up',
                     'topDownload': sorted(users.values(), key=lambda x: x['downloadMbps'], reverse=True)[:20],
                     'topUpload': sorted(users.values(), key=lambda x: x['uploadMbps'], reverse=True)[:20]}
            with self.lock:
                self.value = value
            return True
        except (OSError, ValueError, TypeError):
            self.previous = {}
            with self.lock:
                self.value.update(complete=False, reason='discovery_unavailable',
                                  sources=[], topDownload=[], topUpload=[])
            return False
        finally:
            self.sampling.release()

    def read(self):
        with self.lock:
            value = copy.deepcopy(self.value)
        stamp = value.get('sampleTime')
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(stamp)).total_seconds() if stamp else None
        value['stalenessSeconds'] = age
        value['stale'] = age is None or age < 0 or age > INTERVAL * 3
        if value['stale']:
            value['complete'] = False
            value['reason'] = 'sample_stale' if stamp else 'no_sample'
        return value


hotspots = Hotspots()
_stop = threading.Event()
_thread = None
_lifecycle = threading.Lock()


def _run():
    while not _stop.is_set():
        try:
            hotspots.sample()
        except Exception:
            # No per-connection logs, configs, secrets or new persistence writes.
            pass
        _stop.wait(INTERVAL)


def start():
    global _thread
    # One owner per host. Secondary agents use separate HTTP ports and must
    # not each scan all the same cores; operators may explicitly override.
    from config import config
    default = '1' if config.server.port == 8088 else '0'
    if os.environ.get('NODE_MANAGER_HOTSPOT_MONITOR_ENABLED', default) != '1':
        return
    with _lifecycle:
        if _thread is not None and _thread.is_alive():
            return
        _stop.clear()
        _thread = threading.Thread(target=_run, name='core-hotspots', daemon=True)
        _thread.start()


def stop():
    with _lifecycle:
        _stop.set()
        if _thread is not None:
            _thread.join(timeout=5)
