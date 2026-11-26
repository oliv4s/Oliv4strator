"""Bounded, read-only queries to fixed public vulnerability reference APIs.

Not a network proxy, vulnerability scanner, exploit searcher or scope bypass.
No arbitrary URL, code download, authentication header, redirects or POST.
Remote documents are untrusted reference material, never instructions.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request

from .common import atomic_json
from . import workspace

CVE = re.compile(r'^CVE-\d{4}-\d{4,10}$', re.I)
REPO = re.compile(r'^[A-Za-z0-9_.-]{1,60}/[A-Za-z0-9_.-]{1,100}$')
MAX_DOWNLOAD = 1_500_000
TTL = 6 * 3600


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Research API redirect denied')


def _fetch_json(url: str) -> object:
    """Trusted URLs only, constructed internally by lookup()."""
    parsed = urlsplit(url)
    allowed = ((parsed.hostname == 'services.nvd.nist.gov' and
                parsed.path == '/rest/json/cves/2.0') or
               (parsed.hostname == 'api.github.com' and
                (parsed.path == '/advisories' or
                 (parsed.path.startswith('/repos/') and len(parsed.path.split('/')) == 4))))
    if parsed.scheme != 'https' or not allowed or parsed.port not in (None, 443) or parsed.username:
        raise ValueError('Research source not allowed')
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler())
    req = Request(url, headers={'Accept': 'application/json', 'User-Agent': 'Oliv4strator-Research/1'}, method='GET')
    with opener.open(req, timeout=9) as response:
        if response.status != 200:
            raise ValueError('Research source returned non-200 response')
        payload = response.read(MAX_DOWNLOAD + 1)
    if len(payload) > MAX_DOWNLOAD:
        raise ValueError('Research response exceeds size limit')
    return json.loads(payload)


def _short(value: object, limit: int = 320) -> str:
    if not isinstance(value, str):
        return ''
    value = ''.join(ch for ch in value if ch.isprintable() or ch in '\n\t')
    return ' '.join(value.split())[:limit]


def _nvd(value: object) -> list[dict]:
    rows = value.get('vulnerabilities', []) if isinstance(value, dict) else []
    result = []
    if not isinstance(rows, list):
        raise ValueError('Unexpected NVD response')
    for item in rows[:5]:
        cve = item.get('cve', {}) if isinstance(item, dict) else {}
        if not isinstance(cve, dict):
            continue
        descriptions = cve.get('descriptions', [])
        if not isinstance(descriptions, list):
            descriptions = []
        desc = next((row.get('value', '') for row in descriptions
                     if isinstance(row, dict) and row.get('lang') == 'en'), '')
        identifier = cve.get('id', '')
        if not isinstance(identifier, str) or not CVE.fullmatch(identifier):
            continue
        result.append({'id': identifier, 'summary': _short(desc),
                       'published': cve.get('published'), 'updated': cve.get('lastModified'),
                       'reference': 'https://nvd.nist.gov/vuln/detail/' + identifier})
    return result


def _github_advisories(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError('Unexpected advisory response')
    result = []
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        result.append({'id': _short(item.get('ghsa_id'), 48),
                       'cve_id': _short(item.get('cve_id'), 40),
                       'summary': _short(item.get('summary')),
                       'severity': _short(item.get('severity'), 30),
                       'reference': _short(item.get('html_url'), 240),
                       'updated': item.get('updated_at')})
    return result


def _github_repo(value: object) -> list[dict]:
    if not isinstance(value, dict):
        raise ValueError('Unexpected repository response')
    return [{'repository': _short(value.get('full_name'), 160),
             'description': _short(value.get('description')),
             'archived': value.get('archived'),
             'updated': value.get('updated_at'),
             'reference': _short(value.get('html_url'), 240)}]


def lookup(repo: Path, source: str, *, cve_id: str = '', keyword: str = '',
           repository: str = '') -> dict:
    """Lookup only official metadata/advisories; never execute referenced content."""
    if not all(isinstance(x, str) for x in (source, cve_id, keyword, repository)):
        raise ValueError('Research arguments must be strings')
    if source == 'nvd':
        if cve_id and CVE.fullmatch(cve_id):
            parameters = {'cveId': cve_id.upper()}
        elif (not cve_id and isinstance(keyword, str) and 3 <= len(keyword) <= 80
              and all(c.isprintable() for c in keyword)):
            parameters = {'keywordSearch': keyword, 'resultsPerPage': 5}
        else:
            raise ValueError('NVD requires a CVE ID or a 3..80 character keyword')
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' + urlencode(parameters)
        parser = _nvd
    elif source == 'github_advisory':
        if not CVE.fullmatch(cve_id) or keyword or repository:
            raise ValueError('GitHub advisory lookup requires a CVE ID')
        url = 'https://api.github.com/advisories?' + urlencode({'cve_id': cve_id.upper(), 'per_page': 5})
        parser = _github_advisories
    elif source == 'github_repo':
        if not REPO.fullmatch(repository) or repository.startswith(('.', '-')) or '/.' in repository or '/-' in repository:
            raise ValueError('Repository must be public owner/name')
        if cve_id or keyword:
            raise ValueError('Repository lookup accepts only repository')
        url = 'https://api.github.com/repos/' + repository
        parser = _github_repo
    else:
        raise ValueError('Unknown reference source')

    folder = Path(repo) / 'work' / 'research-cache'
    workspace._directory(folder, create=True)
    key = hashlib.sha256(url.encode()).hexdigest()
    cache = folder / (key + '.json')
    if cache.exists() and not cache.is_symlink():
        item = json.loads(cache.read_text(encoding='utf-8'))
        if isinstance(item, dict) and item.get('url') == url and time.time() - item.get('saved_at', 0) < TTL:
            return {**item['result'], 'cache': 'hit'}
    # Independent lookups share a small per-source rate limit; cache hits above
    # do not consume requests. Keep this under provider unauthenticated limits.
    quota = folder / ('requests-' + source + '.json')
    if quota.is_symlink():
        raise ValueError('Refusing symlink research quota')
    now = time.time()
    previous = json.loads(quota.read_text('utf-8')) if quota.exists() else []
    if not isinstance(previous, list):
        raise ValueError('Invalid research quota record')
    previous = [stamp for stamp in previous if isinstance(stamp, (float, int)) and now - stamp < 60]
    if len(previous) >= (3 if source == 'nvd' else 8):
        raise ValueError('Research source rate limit reached; use cached references')
    atomic_json(quota, previous + [now])
    try:
        records = parser(_fetch_json(url))
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise ValueError(f'Research API unavailable: {type(error).__name__}') from error
    result = {'source': source, 'lookup_url': url, 'retrieved_at': datetime.now(timezone.utc).isoformat(),
              'records': records, 'count': len(records), 'cache': 'miss',
              'note': 'Public metadata only; verify applicability against authorized assets. No exploitation or downloads.'}
    if cache.is_symlink():
        raise ValueError('Refusing symlink research cache')
    atomic_json(cache, {'url': url, 'saved_at': time.time(), 'result': result})
    return result
