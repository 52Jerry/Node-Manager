"""Retire old VLESS generations only after native socket and Clash checks agree."""
import json, os, pathlib, subprocess, sys, datetime

ROOT=pathlib.Path('/opt/node-manager-releases/runtime-r3-20261028-01')
sys.path.insert(0,str(ROOT/'node-manager'))
import vless_publication as publication
import rolling_runtime as rolling

SPEC=pathlib.Path('/etc/niusu-vless-publication/spec.json')
REPORT=ROOT/'old-generation-drain.json'

def run(*args):
    process=subprocess.run(args,capture_output=True,text=True,timeout=15)
    return process.returncode,process.stdout.strip()

def report(result):
    result['atUtc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    temp=REPORT.with_suffix('.tmp')
    temp.write_text(json.dumps(result,indent=2))
    os.chmod(temp,0o600)
    os.replace(temp,REPORT)
    print(json.dumps(result))

def main():
    if not SPEC.is_file():raise RuntimeError('legacy_spec_missing')
    spec=json.loads(SPEC.read_text())
    state=publication.load_state(spec)
    executable=os.readlink('/proc/'+run('systemctl','show','sing-box.service','-p','MainPID','--value')[1]+'/exe')
    if executable!='/usr/local/libexec/sing-box-niusu-r3':raise RuntimeError('new_core_not_active')
    if not pathlib.Path('/run/sing-box/users.sock').is_socket():raise RuntimeError('runtime_socket_missing')
    rules=run('iptables','-t','nat','-S')[1]
    for line in rules.splitlines():
        if line.startswith(('-A PREROUTING','-A OUTPUT')) and 'NIUSU_VLESS_ACTIVE' in line:
            raise RuntimeError('old_route_still_active')
    if run('systemctl','is-enabled','niusu-vless-publication-bootstrap.service')[1]=='enabled':
        raise RuntimeError('old_bootstrap_still_enabled')
    if state['phase']!='steady':raise RuntimeError('legacy_journal_not_steady')
    if state['activeId']!='baseline':
        backup=ROOT/'state-before-drain.json'
        if backup.exists():raise RuntimeError('drain_backup_already_exists')
        backup.write_bytes(pathlib.Path(spec['statePath']).read_bytes());os.chmod(backup,0o600)
        state['activeId']='baseline'
        publication.write_state(spec,state)
    before=len(state['generations'])
    after=publication.collect_empty(spec,state)
    report({'before':before,'remaining':len(after['generations']),'retired':before-len(after['generations'])})

if __name__=='__main__':main()
