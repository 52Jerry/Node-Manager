"""Bounded passive kernel counters. None means unavailable, never healthy zero."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess


def cli_counters():
    try:
        result = subprocess.run(['conntrack', '-S'], capture_output=True, text=True, timeout=1)
        if result.returncode or len(result.stdout) > 1 << 20:
            return None
        sums = {}
        for line in result.stdout.splitlines():
            for key, value in re.findall(r'\b(insert_failed|drop|early_drop|invalid|search_restart)=(\d+)\b', line):
                sums[key] = sums.get(key, 0) + int(value)
        return sums or None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def read(proc=Path('/proc'), fallback=cli_counters):
    result = {'conntrack': {}, 'conntrackCounters': None, 'tcpCounters': None}
    for name in ('count', 'max'):
        try:
            result['conntrack'][name] = int((proc / 'sys/net/netfilter' / ('nf_conntrack_' + name)).read_text())
        except (OSError, ValueError):
            result['conntrack'][name] = None
    count, maximum = result['conntrack']['count'], result['conntrack']['max']
    result['conntrack']['usagePercent'] = count * 100 / maximum if count is not None and maximum else None
    try:
        lines = (proc / 'net/stat/nf_conntrack').read_text().splitlines()
        names, sums = lines[0].split(), {}
        if len(lines) < 2:
            raise ValueError('empty_counters')
        for line in lines[1:]:
            values = line.split()
            if len(values) != len(names):
                raise ValueError('invalid_counters')
            for key, value in zip(names, values):
                if key in ('insert_failed', 'drop', 'early_drop', 'invalid', 'search_restart'):
                    sums[key] = sums.get(key, 0) + int(value, 16)
        result['conntrackCounters'] = sums or None
    except (OSError, ValueError, IndexError):
        pass
    if result['conntrackCounters'] is None:
        result['conntrackCounters'] = fallback()
    try:
        lines = (proc / 'net/netstat').read_text().splitlines()
        wanted = {'ListenDrops', 'ListenOverflows', 'TCPMemoryPressures', 'TCPRcvQDrop', 'TCPBacklogDrop'}
        for first, second in zip(lines[::2], lines[1::2]):
            names, values = first.split(), second.split()
            if names[0] != 'TcpExt:' or values[0] != 'TcpExt:' or len(names) != len(values):
                continue
            result['tcpCounters'] = {key: int(value) for key, value in zip(names[1:], values[1:]) if key in wanted}
    except (OSError, ValueError, IndexError):
        pass
    return result


def difference(current, previous):
    def delta(name):
        new, old = current.get(name), previous.get(name) if previous else None
        if not new or not old or set(new) != set(old) or any(new[k] < old[k] for k in new):
            return None
        return {key: value - old[key] for key, value in new.items()}
    return {'conntrack': current['conntrack'], 'conntrackCounterDelta': delta('conntrackCounters'),
            'tcpCounterDelta': delta('tcpCounters'),
            'tcpScope': 'locally_terminated_connections_not_forwarded_tcp'}
