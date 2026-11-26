#!/usr/bin/env python3
"""Read-only local MCP configuration diagnosis; never prints secrets or executes a server."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import sys


def check_config(repo: Path, config: Path) -> dict:
    if not config.is_file():
        return {'config':str(config), 'exists':False,'ok':False,
                'note':'No project config at this path; server may be configured elsewhere.'}
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        raise RuntimeError('Python 3.11+ required for TOML preflight')
    obj=tomllib.loads(config.read_text(encoding='utf-8'))
    section=obj.get('mcp_servers',{}).get('oliva_lab',{})
    if not section:
        return {'config':str(config),'exists':True,'ok':False,
                'note':'No oliva_lab entry in this file; may be configured globally.'}
    command=section.get('command','')
    args=section.get('args',[])
    cwd=section.get('cwd')
    if not isinstance(command,str) or not isinstance(args,list):
        return {'config':str(config),'exists':True,'ok':False,'note':'Malformed command or args'}
    executable=Path(command).is_file() if Path(command).is_absolute() else bool(shutil.which(command))
    missing_paths=[]
    for arg in args:
        # Do not print arguments, credentials, endpoint URLs or env variables.
        if isinstance(arg,str) and arg.endswith('.py'):
            p=Path(arg)
            if not p.is_absolute():
                p=(Path(cwd) if isinstance(cwd,str) else repo)/p
            if not p.is_file():
                missing_paths.append('python_entrypoint_missing')
    cwd_ok = cwd is None or (isinstance(cwd,str) and Path(cwd).is_dir())
    return {'config':str(config),'exists':True,'ok':bool(executable and cwd_ok and not missing_paths),
            'executable_exists':bool(executable),'cwd_exists':cwd_ok,'entrypoint_check':missing_paths,
            'note':'Static check only; no server or API endpoint was contacted.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',type=Path,default=Path.cwd())
    p.add_argument('--config',type=Path)
    opts=p.parse_args()
    repo=opts.repo.resolve()
    config=opts.config or repo/'.codex/config.toml'
    import json
    try:
        info=check_config(repo,config)
    except (ValueError,RuntimeError) as exc:
        p.exit(2,str(exc)+'\n')
    print(json.dumps(info,indent=2))
    if not info['ok']:
        p.exit(1)
if __name__=='__main__':
    main()
