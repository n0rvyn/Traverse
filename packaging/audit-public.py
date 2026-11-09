"""Audit the exact staged import; never print a secret's matched value."""
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parent.parent
policy=json.loads((ROOT/'packaging/public-files.json').read_text())
paths=subprocess.check_output(['git','diff','--cached','--name-only','--diff-filter=ACMR','-z'],cwd=ROOT).decode().split('\0')
patterns=[r'[-]{5}BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY[-]{5}',r'\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}',r'\bAKIA[A-Z0-9]{16}\b',r'\bsk-[A-Za-z0-9]{20,}',r'Bearer [A-Za-z0-9._-]{24,}']
operator_policy=ROOT/'docs/private/publication-denylist.json'
operator_literals=json.loads(operator_policy.read_text()) if operator_policy.exists() else []
failures=[]
for name in filter(None,paths):
    path=Path(name)
    if name not in policy['files'] and not any(path.is_relative_to(d) for d in policy['directories']):failures.append(name+': outside publication allowlist');continue
    data=subprocess.check_output(['git','show',':'+name],cwd=ROOT)
    if len(data)>500_000:failures.append(name+': oversized file')
    if '__pycache__' in path.parts or path.suffix in ('.pem','.key','.p12'):failures.append(name+': private/generated file')
    try:text=data.decode()
    except UnicodeDecodeError:failures.append(name+': unexpected binary');continue
    for line_no,line in enumerate(text.splitlines(),1):
        if any(re.search(pattern,line) for pattern in patterns) or any(value in line for value in operator_literals):failures.append(f'{name}:{line_no}: credential/private-deployment pattern')
if failures:raise SystemExit('\n'.join(failures))
print('Staged publication allowlist/credential audit passed: '+str(len(list(filter(None,paths))))+' files')
