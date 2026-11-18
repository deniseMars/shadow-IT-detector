"""Read-only Windows inventory. Python 3.9+, standard library only.

Run: py -3 inventory_windows.py
Outputs: inventory/windows/<UTC timestamp>/{packages.csv,packages.json,raw.json,scan.log}
No credentials or computer-specific inventory are embedded in this template.
"""
import base64
from collections import Counter
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def command_result(command):
    """Run a local query, preserving failures rather than claiming a clean scan."""
    actual = command
    if Path(command[0]).suffix.lower() in ('.cmd', '.bat'):
        # PowerShell literal arguments avoid shell interpolation of local paths.
        quote = lambda s: "'" + s.replace("'", "''") + "'"
        script = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); & " + ' '.join(map(quote, command)) + '; exit $LASTEXITCODE'
        actual = ['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                  base64.b64encode(script.encode('utf-16le')).decode('ascii')]
    try:
        p = subprocess.run(actual, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=90,
                           env=dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK='1', PYTHONIOENCODING='utf-8'))
        return dict(command=command, exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)
    except (OSError, subprocess.TimeoutExpired) as e:
        return dict(command=command, error=str(e))


def collect_registry(add, errors):
    import winreg
    uninstall = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    seen = set()
    for hive_name, hive in [('HKLM', winreg.HKEY_LOCAL_MACHINE), ('HKCU', winreg.HKEY_CURRENT_USER)]:
        for view_name, view in [('64', winreg.KEY_WOW64_64KEY), ('32', winreg.KEY_WOW64_32KEY)]:
            source = f'{hive_name}/{view_name}/{uninstall}'
            try:
                with winreg.OpenKey(hive, uninstall, 0, winreg.KEY_READ | view) as root:
                    for i in range(winreg.QueryInfoKey(root)[0]):
                        key_name = winreg.EnumKey(root, i)
                        try:
                            with winreg.OpenKey(root, key_name) as key:
                                def value(name):
                                    try:
                                        return str(winreg.QueryValueEx(key, name)[0])
                                    except FileNotFoundError:
                                        return ''
                                name, version = value('DisplayName'), value('DisplayVersion')
                                identity = (hive_name, key_name, name, version)
                                if name and identity not in seen:
                                    add('windows-app', name, version, source + '/' + key_name)
                                    seen.add(identity)
                        except OSError as e:
                            errors.append(f'{source}/{key_name}: {e}')
            except FileNotFoundError:
                pass  # This registry view need not exist.
            except OSError as e:
                errors.append(f'{source}: {e}')


def main():
    if sys.platform != 'win32':
        print('This script must be run on Windows; no scan was performed.', file=sys.stderr)
        return 1
    timestamp = datetime.now(timezone.utc)
    out = Path(__file__).resolve().parent / 'inventory' / 'windows' / timestamp.strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True, exist_ok=False)
    rows, errors, skipped, raw = [], [], [], {}
    def add(ecosystem, name, version, source):
        rows.append(dict(ecosystem=ecosystem, name=str(name), version=str(version), source=str(source)))
    def query(label, command):
        result = raw[label] = command_result(command)
        if result.get('exit_code', 1) != 0:
            errors.append(label + ': ' + (result.get('error') or result.get('stderr') or 'command failed'))
            return None
        try:
            return json.loads(result['stdout'].lstrip('\ufeff'))
        except (ValueError, TypeError) as e:
            errors.append(f'{label}: invalid JSON: {e}')
            return None

    collect_registry(add, errors)
    # The interpreter running this script; does not discover every virtual environment.
    data = query('python-pip', [sys.executable, '-m', 'pip', 'list', '--format=json'])
    if isinstance(data, list):
        for item in data:
            add('pypi', item['name'], item['version'], sys.executable)
    npm = shutil.which('npm.cmd') or shutil.which('npm')
    if npm:
        data = query('npm-global', [npm, 'ls', '-g', '--json', '--depth=0'])
        if isinstance(data, dict):
            for name, item in data.get('dependencies', {}).items():
                add('npm', name, item.get('version', ''), 'global')
    else:
        skipped.append('npm: not found on PATH')
    conda = shutil.which('conda.exe') or shutil.which('conda.bat') or shutil.which('conda')
    if conda:
        data = query('conda-environments', [conda, 'env', 'list', '--json'])
        if isinstance(data, dict):
            for i, prefix in enumerate(data.get('envs', [])):
                packages = query(f'conda-{i}', [conda, 'list', '--prefix', prefix, '--json'])
                if isinstance(packages, list):
                    for item in packages:
                        add('pypi' if item.get('channel') == 'pypi' else 'conda', item['name'], item['version'], prefix)
    else:
        skipped.append('conda: not found on PATH')

    limitations = [
        'Partial inventory: registry-listed applications, this Python interpreter, global npm and discoverable Conda environments only.',
        'Microsoft Store apps, portable apps, project dependencies, other Python interpreters/virtual environments, WSL, containers and other users may be absent.',
        'Registry entries may be stale; versions may be absent. Sources can overlap.',
        'No vulnerability assessment, Feedly query, network capture or historical installation log is performed.',
        'Outputs may contain usernames and local paths. Review before sharing.'
    ]
    report = dict(collected_at=timestamp.isoformat(), packages=rows, incomplete_sources=errors,
                  skipped_sources=skipped, limitations=limitations)
    (out / 'packages.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (out / 'raw.json').write_text(json.dumps(raw, indent=2), encoding='utf-8')
    with (out / 'packages.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=['ecosystem', 'name', 'version', 'source'])
        writer.writeheader()
        writer.writerows(rows)
    summary = dict(collected_at=timestamp.isoformat(), records=len(rows), counts=dict(Counter(r['ecosystem'] for r in rows)),
                   incomplete_sources=errors, skipped_sources=skipped, output=str(out))
    log = json.dumps(summary, indent=2)
    (out / 'scan.log').write_text(log + '\n', encoding='utf-8')
    print(log)
    return 2 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
