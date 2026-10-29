#!/usr/bin/env python3
"""Offline structural checks for owned documentation and packaging templates."""
import ast
import json
import pathlib
import plistlib
import re
import subprocess
import xml.etree.ElementTree as ET

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    count = 0
    for base in ('.github', 'packaging', 'deploy', 'docs'):
        for file in (ROOT / base).rglob('*'):
            if not file.is_file() or '__pycache__' in file.parts:
                continue
            suffix = file.suffix
            if suffix in ('.yaml', '.yml') and '{{' not in file.read_text(encoding='utf-8'):
                list(yaml.safe_load_all(file.read_text(encoding='utf-8')))
            elif suffix == '.json':
                json.loads(file.read_text(encoding='utf-8'))
            elif suffix == '.py':
                ast.parse(file.read_text(encoding='utf-8'), filename=str(file))
            elif suffix == '.sh':
                subprocess.run(['sh', '-n', str(file)], check=True)
            elif suffix in ('.xml', '.wxs'):
                ET.parse(file)
            elif suffix == '.plist':
                plistlib.loads(file.read_bytes())
            elif suffix == '.md':
                for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', file.read_text(encoding='utf-8')):
                    target = target.split('#', 1)[0]
                    if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                        continue
                    if not (file.parent / target).exists():
                        raise ValueError(f'{file.relative_to(ROOT)}: broken local link {target}')
            count += 1
    print(f'Validated syntax and local document links in {count} files')


if __name__ == '__main__':
    main()
