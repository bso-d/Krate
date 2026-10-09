"""Licence lookup through the deps.dev (Open Source Insights) batch API.

deps.dev only *classifies* here; it never supplies source. Every source file is
downloaded from the ecosystem's own registry and verified there."""
from __future__ import annotations

import json
import urllib.request

from common import USER_AGENT, log

API = 'https://api.deps.dev/v3alpha/versionbatch'


def licences(cache, system, keys):
    """keys: iterable of (name, version). Returns {(name, version): [spdx, ...] | None}."""
    keys = sorted(set(keys))
    out, todo = {}, []
    for k in keys:
        path = cache.meta_path(f'depsdev:{system}:{k[0]}@{k[1]}')
        if path.exists():
            out[k] = json.loads(path.read_text())
        else:
            todo.append(k)
    for i in range(0, len(todo), 400):
        chunk = todo[i:i + 400]
        body = json.dumps({'requests': [{'versionKey': {'system': system, 'name': n, 'version': v}}
                                        for n, v in chunk]}).encode()
        page_token, got = None, {}
        while True:
            payload = json.loads(body)
            if page_token:
                payload['pageToken'] = page_token
            req = urllib.request.Request(API, data=json.dumps(payload).encode(), method='POST',
                                         headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/json'})
            data = {'responses': []}
            for attempt in range(4):
                try:
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        data = json.loads(resp.read())
                    break
                except Exception as exc:  # retry transient errors
                    if attempt == 3:
                        log(f'deps.dev batch failed: {exc}')
            for r in data.get('responses', []):
                vk = r['request']['versionKey']
                ver = r.get('version')
                got[(vk['name'], vk['version'])] = (ver.get('licenses') or None) if ver else None
            page_token = data.get('nextPageToken')
            if not page_token:
                break
        for k in chunk:
            val = got.get(k)
            out[k] = val
            if k in got:  # do not cache a failed request as "no licence"
                cache.meta_path(f'depsdev:{system}:{k[0]}@{k[1]}').write_text(json.dumps(val))
    return out
