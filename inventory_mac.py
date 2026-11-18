"""Read-only inventory; does not install, update, or remove packages."""
import concurrent.futures
import csv
import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

OUT = Path(__file__).resolve().parent / 'inventory'
OUT.mkdir(exist_ok=True)
env = dict(os.environ, HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_ANALYTICS='1', PIP_DISABLE_PIP_VERSION_CHECK='1')

def run(label, command):
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=90, env=env)
        return label, dict(command=command, exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)
    except Exception as e:
        return label, dict(command=command, error=str(e))

jobs = []
for tool, label, args in [('brew','homebrew',['info','--installed','--json=v2']), ('npm','npm-global',['ls','-g','--json','--depth=0']), ('conda','conda-environments',['env','list','--json']), ('gem','ruby-gems',['list','--local'])]:
    binary = shutil.which(tool)
    if binary:
        jobs.append((label, [binary] + args))
interpreters = {str(Path(p).resolve()) for p in [shutil.which('python3'), '/usr/bin/python3', '/opt/miniconda3/bin/python'] if p and Path(p).exists()}
for i, binary in enumerate(sorted(interpreters)):
    jobs.append((f'python-{i}', [binary, '-m', 'pip', 'list', '--format=json']))
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    raw = dict(pool.map(lambda job: run(*job), jobs))

rows = []
def add(ecosystem, name, version, source):
    rows.append(dict(ecosystem=ecosystem, name=name, version=version, source=source))
errors = []
for label, result in list(raw.items()):
    if result.get('exit_code', 1) != 0:
        errors.append(label)
        continue
    try:
        if label == 'homebrew':
            data = json.loads(result['stdout'])
            for item in data.get('formulae', []):
                for installed in item.get('installed', []):
                    add('homebrew', item['name'], installed.get('version',''), label)
            for item in data.get('casks', []):
                versions = item.get('installed', [])
                for version in versions if isinstance(versions, list) else [versions]:
                    add('homebrew-cask', item['token'], version, label)
        elif label.startswith('python-'):
            for item in json.loads(result['stdout']):
                add('pypi', item['name'], item['version'], result['command'][0])
        elif label == 'npm-global':
            for name, item in json.loads(result['stdout']).get('dependencies', {}).items():
                add('npm', name, item.get('version',''), 'global')
        elif label == 'conda-environments':
            for i, prefix in enumerate(json.loads(result['stdout']).get('envs', [])):
                key, data = run(f'conda-{i}', [shutil.which('conda'), 'list', '--prefix', prefix, '--json'])
                raw[key] = data
                if data.get('exit_code',1) != 0:
                    errors.append(key)
                    continue
                for item in json.loads(data['stdout']):
                    add('pypi' if item.get('channel') == 'pypi' else 'conda', item['name'], item['version'], prefix)
        elif label == 'ruby-gems':
            for line in result['stdout'].splitlines():
                if ' (' in line:
                    name, versions = line.split(' (',1)
                    for version in versions.rstrip(')').split(', '):
                        add('rubygems', name, version.removeprefix('default: '), label)
    except Exception as e:
        errors.append(f'{label}: {e}')

# Metadata can be read even when an older Conda binary cannot execute.
prefixes = {Path('/opt/miniconda3')}
env_list = Path.home() / '.conda/environments.txt'
if env_list.exists():
    prefixes.update(Path(line.strip()) for line in env_list.read_text().splitlines() if line.strip())
prefixes.update(Path('/opt/miniconda3/envs').glob('*'))
known = {(r['name'], r['version'], r['source']) for r in rows}
for prefix in prefixes:
    for metadata in (prefix / 'conda-meta').glob('*.json'):
        try:
            item = json.loads(metadata.read_text())
            key = (item['name'], item['version'], str(prefix))
            if key not in known:
                add('conda', *key)
                known.add(key)
        except (OSError, ValueError, KeyError):
            errors.append(str(metadata))

for base in [Path('/Applications'), Path.home() / 'Applications']:
    for app in base.glob('*.app'):
        try:
            with (app / 'Contents/Info.plist').open('rb') as f:
                info = plistlib.load(f)
            add('macos-app', info.get('CFBundleIdentifier',app.stem), info.get('CFBundleShortVersionString', info.get('CFBundleVersion','')), str(app))
        except (OSError, ValueError, plistlib.InvalidFileException):
            errors.append(str(app))

report = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), packages=rows, incomplete_sources=errors, limitations=['Project dependencies, unlisted virtual environments, containers, nested applications and other user accounts are not inventoried.', 'Inventory is not a vulnerability or exploitation assessment.'])
(OUT / 'packages.json').write_text(json.dumps(report, indent=2))
(OUT / 'raw.json').write_text(json.dumps(raw, indent=2))
with (OUT / 'packages.csv').open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['ecosystem','name','version','source'])
    writer.writeheader()
    writer.writerows(rows)
counts = {}
for row in rows:
    counts[row['ecosystem']] = counts.get(row['ecosystem'],0) + 1
print(json.dumps(dict(counts=counts, incomplete_sources=errors, output=str(OUT)), indent=2))
