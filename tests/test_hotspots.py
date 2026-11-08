import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from monitor import capacity_counters as counters
from monitor import hotspots as hs


def frame(*rows):
    return {'connections': [{'id': cid, 'chains': ['node-manager-out:' + uid],
                             'upload': up, 'download': down,
                             'metadata': {'sourceIP': '172.16.80.15', 'host': 'private.test',
                                          'user': 'secret-password'}}
                            for cid, uid, up, down in rows]}


def core(pid=1, start=100, port=9090):
    return hs.Core(pid, start, port, 'secret-api-token', [{'protocol': 'vless', 'port': 20168}],
                   {'primary-1': '192.0.2.1'})


def kernel():
    return {'conntrack': {'count': 5, 'max': 100, 'usagePercent': 5},
            'conntrackCounters': {'drop': 1}, 'tcpCounters': {'ListenDrops': 0}}


def sample(monitor, sources, frames, at, errors=0):
    return monitor.sample(lambda: (sources, errors), lambda c: frames[c.key], lambda: at, kernel)


def test_all_cores_same_user_merge_and_connection_ids_are_namespaced():
    monitor = hs.Hotspots()
    cores = [core(1), core(2, port=62910), core(3, port=9091)]
    frames = {c.key: frame(('same-id', 'primary-1', 100, 200)) for c in cores}
    sample(monitor, cores, frames, 0)
    assert not monitor.read()['complete']
    for f in frames.values():
        f['connections'][0]['download'] += 1_250_000
    sample(monitor, cores, frames, 10)
    result = monitor.read()
    assert result['complete']
    assert result['topDownload'][0]['downloadMbps'] == 3
    assert result['topDownload'][0]['matchedConnections'] == 3
    assert result['topDownload'][0]['residentialIP'] == '192.0.2.1'
    rendered = json.dumps(result)
    for secret in ['secret-api-token', 'secret-password', 'private.test', '172.16.80.15', 'same-id']:
        assert secret not in rendered


def test_pid_reuse_and_counter_resets_do_not_report_spikes():
    monitor = hs.Hotspots()
    a, b = core(), core(start=101)
    sample(monitor, [a], {a.key: frame(('a', 'primary-1', 10, 10000000))}, 0)
    sample(monitor, [b], {b.key: frame(('a', 'primary-1', 10, 20000000))}, 10)
    assert monitor.read()['topDownload'] == []
    assert not monitor.read()['complete']
    sample(monitor, [b], {b.key: frame(('a', 'primary-1', 0, 1))}, 20)
    assert monitor.read()['sources'][0]['counterResetsExcluded'] == 1
    assert monitor.read()['topDownload'] == []


def test_old_and_current_core_resource_conflict_is_not_silently_overwritten():
    monitor, a, b = hs.Hotspots(), core(), core(2, port=62910)
    b.resources['primary-1'] = '192.0.2.2'
    frames = {c.key: frame(('a', 'primary-1', 0, 100)) for c in [a, b]}
    sample(monitor, [a, b], frames, 0)
    sample(monitor, [a, b], frames, 10)
    item = monitor.read()['topDownload'][0]
    assert item['resourceIdentityConflict']
    assert item['residentialIPs'] == ['192.0.2.1', '192.0.2.2']
    assert 'residentialIP' not in item


def test_new_closed_and_changed_owner_sessions_are_explicitly_excluded():
    monitor, a = hs.Hotspots(), core()
    sample(monitor, [a], {a.key: frame(('closed', 'primary-1', 0, 10), ('changed', 'primary-1', 0, 10))}, 0)
    sample(monitor, [a], {a.key: frame(('new', 'primary-1', 0, 90000000), ('changed', 'primary-2', 0, 20))}, 10)
    result = monitor.read()
    status = result['sources'][0]
    assert status['closedConnectionsExcluded'] == 1
    assert status['newConnectionsExcluded'] == 1
    assert status['counterResetsExcluded'] == 1
    assert result['topDownload'] == []
    assert result['measurementBasis'] == 'matched_live_sessions_only_not_billing'


def test_failed_core_makes_partial_snapshot_and_recovery_warms_up():
    monitor, a, b = hs.Hotspots(), core(), core(2, port=9091)
    frames = {c.key: frame(('a', 'primary-1', 0, 100)) for c in [a, b]}
    sample(monitor, [a, b], frames, 0)
    frames[b.key] = None
    sample(monitor, [a, b], frames, 10)
    result = monitor.read()
    assert not result['complete']
    assert not result['sources'][1]['available']
    assert 'downloadMbps' not in result['sources'][1]
    frames[b.key] = frame(('a', 'primary-1', 0, 90000000))
    sample(monitor, [a, b], frames, 20)
    assert result['sources'][1]['reason'] == 'core_snapshot_unavailable'
    assert monitor.read()['sources'][1]['reason'] == 'warming_up'


@pytest.mark.parametrize('bad', [True, -1, '9', 2**63])
def test_bad_counter_rejects_source(bad):
    with pytest.raises(ValueError):
        hs.project(frame(('a', 'primary-1', 0, bad)))


def test_duplicate_ids_and_ambiguous_user_are_rejected():
    with pytest.raises(ValueError):
        hs.project(frame(('a', 'primary-1', 0, 1), ('a', 'primary-2', 0, 1)))
    value = frame(('a', 'primary-1', 0, 1))
    value['connections'][0]['chains'].append('node-manager-out:primary-2')
    with pytest.raises(ValueError):
        hs.project(value)


def test_unknown_user_not_invented_from_snat_ip():
    monitor, a = hs.Hotspots(), core()
    sample(monitor, [a], {a.key: frame(('a', 'unsafe-secret', 0, 0))}, 0)
    sample(monitor, [a], {a.key: frame(('a', 'unsafe-secret', 0, 1_250_000))}, 10)
    row = monitor.read()['topDownload'][0]
    assert row['nodeUserId'] is None
    assert row['downloadMbps'] == 1
    assert 'unsafe-secret' not in json.dumps(monitor.read())


def test_stale_cache_read_never_fetches_or_blocks_on_sample():
    monitor = hs.Hotspots()
    monitor.value.update(sampleTime=(datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat(), complete=True)
    monitor.sampling.acquire()
    try:
        assert not monitor.sample(discover_fn=lambda: pytest.fail('must not discover'))
        assert monitor.read()['stale']
        assert not monitor.read()['complete']
        assert monitor.read()['reason'] == 'sample_stale'
    finally:
        monitor.sampling.release()


def test_discovery_errors_and_no_cores_never_claim_complete():
    monitor, a = hs.Hotspots(), core()
    for at in [0, 10]:
        sample(monitor, [a], {a.key: frame()}, at, errors=1)
    assert not monitor.read()['complete']
    sample(monitor, [], {}, 20)
    assert not monitor.read()['complete']


def fake_proc(tmp_path, pid=1, port=9090, unit='sing-box.service'):
    proc = tmp_path / 'proc'
    base = proc / str(pid)
    base.mkdir(parents=True)
    (base / 'comm').write_text('sing-box\n')
    (base / 'cgroup').write_text('0::/system.slice/' + unit + '\n')
    (base / 'stat').write_text(f'{pid} (sing box) ' + ' '.join(['S'] + ['0'] * 18 + ['100'] + ['0'] * 5))
    config = tmp_path / (str(pid) + '.json')
    config.write_text(json.dumps({'experimental': {'clash_api': {'external_controller': f'127.0.0.1:{port}',
                                                                 'secret': 'never-show'}},
                                 'inbounds': [{'type': 'vless', 'listen_port': 20168}]}))
    (base / 'cmdline').write_bytes(('sing-box\0run\0-c\0' + str(config) + '\0').encode())
    return proc, config


def test_discovery_includes_owned_draining_cores_ignores_foreign_processes(tmp_path):
    proc, _ = fake_proc(tmp_path)
    fake_proc(tmp_path, 2, 62900, 'niusu-vless-gen-abcdef123456.service')
    fake_proc(tmp_path, 3, 9091, 'unrelated.service')
    cores, errors = hs.discover(proc)
    assert {c.pid for c in cores} == {1, 2}
    assert not errors
    assert all('never-show' not in repr(c) for c in cores)


def test_discovery_refuses_external_or_duplicate_controller(tmp_path):
    proc, config = fake_proc(tmp_path)
    cfg = json.loads(config.read_text())
    cfg['experimental']['clash_api']['external_controller'] = 'example.com:9090'
    config.write_text(json.dumps(cfg))
    assert hs.discover(proc) == ([], 1)
    cfg['experimental']['clash_api']['external_controller'] = '127.0.0.1:9090'
    config.write_text(json.dumps(cfg))
    fake_proc(tmp_path, 2, 9090)
    cores, errors = hs.discover(proc)
    assert len(cores) == 1 and errors == 1


def test_kernel_missing_reset_and_low_occupancy_insert_failures(tmp_path):
    proc = tmp_path / 'proc'
    proc.mkdir()
    missing = counters.read(proc, fallback=lambda: None)
    assert missing['conntrack']['usagePercent'] is None
    assert counters.difference(missing, missing)['conntrackCounterDelta'] is None
    old = kernel()
    new = copy.deepcopy(old)
    new['conntrackCounters']['drop'] += 8
    result = counters.difference(new, old)
    assert result['conntrack']['usagePercent'] == 5
    assert result['conntrackCounterDelta']['drop'] == 8
    assert counters.difference(old, new)['conntrackCounterDelta'] is None


def test_kernel_per_cpu_counter_sum_and_invalid_rows(tmp_path):
    proc = tmp_path
    (proc / 'net/stat').mkdir(parents=True)
    (proc / 'net/stat/nf_conntrack').write_text('entries insert_failed drop\n10 01 02\n10 03 04\n')
    assert counters.read(proc, fallback=lambda: None)['conntrackCounters'] == {'insert_failed': 4, 'drop': 6}
    (proc / 'net/stat/nf_conntrack').write_text('entries insert_failed drop\n10 01\n')
    assert counters.read(proc, fallback=lambda: None)['conntrackCounters'] is None


def test_kernel_cli_fallback_is_bounded_and_keeps_real_failures(tmp_path):
    from types import SimpleNamespace
    with patch.object(counters.subprocess, 'run', return_value=SimpleNamespace(
            returncode=0, stdout='cpu=0 insert_failed=3 drop=3 invalid=8\ncpu=1 insert_failed=2 drop=2 invalid=4\n')) as call:
        result = counters.read(tmp_path)
        assert result['conntrackCounters']['insert_failed'] == 5
        assert result['conntrackCounters']['drop'] == 5
        assert call.call_args.kwargs['timeout'] == 1
        assert call.call_args.args[0] == ['conntrack', '-S']
    with patch.object(counters.subprocess, 'run', side_effect=FileNotFoundError()):
        assert counters.read(tmp_path)['conntrackCounters'] is None


def test_many_readers_do_not_wait_for_a_slow_core_or_trigger_more_fetches():
    monitor, a = hs.Hotspots(), core()
    started, release = threading.Event(), threading.Event()
    def fetch(_):
        started.set()
        assert release.wait(5)
        return frame()
    worker = threading.Thread(target=lambda: monitor.sample(lambda: ([a], 0), fetch,
                                                            lambda: 0, kernel))
    worker.start()
    try:
        assert started.wait(2)
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(monitor.read) for _ in range(100)]
            assert all(f.result(timeout=1)['reason'] == 'no_sample' for f in futures)
        assert not monitor.sample(discover_fn=lambda: pytest.fail('no overlapping scan'))
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive()


def test_endpoint_auth_no_store_and_no_live_queries(monkeypatch):
    from main import traffic_hotspots_endpoint
    app = FastAPI()
    app.get('/api/node/traffic-hotspots')(traffic_hotspots_endpoint)
    monkeypatch.setattr(hs.hotspots, 'sample', lambda: pytest.fail('API must only read cache'))
    with TestClient(app) as client:
        assert client.get('/api/node/traffic-hotspots').status_code in (401, 403)
        response = client.get('/api/node/traffic-hotspots', headers={'Authorization': 'Bearer test-token'})
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store'
        assert response.json()['complete'] is False


def test_secondary_agent_does_not_start_a_duplicate_global_scanner(monkeypatch):
    from config import config
    monkeypatch.delenv('NODE_MANAGER_HOTSPOT_MONITOR_ENABLED', raising=False)
    monkeypatch.setattr(config.server, 'port', 8089)
    with patch.object(hs.threading, 'Thread') as factory:
        hs.start()
        factory.assert_not_called()


def test_lifecycle_start_is_singleton_and_explicit_disable_is_respected(monkeypatch):
    monkeypatch.setenv('NODE_MANAGER_HOTSPOT_MONITOR_ENABLED', '0')
    with patch.object(hs.threading, 'Thread') as factory:
        hs.start()
        factory.assert_not_called()
        monkeypatch.setenv('NODE_MANAGER_HOTSPOT_MONITOR_ENABLED', '1')
        with patch.object(hs, '_thread', None):
            hs.start()
            hs.start()
            factory.assert_called_once()
            factory.return_value.start.assert_called_once()
