"""Extract route candidates from one program response without fetching them."""

from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, urljoin, urlsplit
import xml.etree.ElementTree as ET

import program_policy
import scope_target


MAX_CANDIDATES = 200  # Output size limit, not a network request limit.
JS_PATH = re.compile(r"(['\"`])((?:https?://[^'\"`\s\\]{1,300}|/(?!/)[A-Za-z0-9_~@%+./?&=:-]{1,200}))\1", re.I)
STATIC_SUFFIXES = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                   ".ico", ".woff", ".woff2", ".ttf", ".map")


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "title":
            self._in_title = True
        for attribute in ("href", "src", "action"):
            value = values.get(attribute)
            if value and tag in {"a", "link", "script", "form", "img", "iframe"}:
                self.references.append((value, f"html_{tag}_{attribute}"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 160:
            self.title += data[:160 - len(self.title)]


def extract(policy: dict, source_url: str, body: str, content_type: str = "") -> dict:
    """Return candidate URLs and scope hints; never visit extracted links."""
    references: list[tuple[str, str]] = []
    title = ""
    path = urlsplit(source_url).path.lower()
    kind = "text"
    if "html" in content_type.lower() or body.lstrip().lower().startswith(("<!doctype html", "<html")):
        parsed = Links()
        parsed.feed(body)
        references = parsed.references
        title = parsed.title.strip()
        kind = "html"
    elif "xml" in content_type.lower() or path.endswith(("sitemap.xml", ".xml")):
        try:
            root = ET.fromstring(body)
            references = [(node.text.strip(), "sitemap_loc") for node in root.iter()
                          if node.tag.rsplit("}", 1)[-1].lower() == "loc" and node.text and node.text.strip()]
            kind = "xml"
        except ET.ParseError:
            kind = "text"
    elif path.endswith("robots.txt") or body.lstrip().lower().startswith("user-agent:"):
        for line in body.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip().lower() in {"allow", "disallow", "sitemap"} and value.strip():
                references.append((value.strip().split("#", 1)[0].strip(),
                                   "robots_" + key.strip().lower()))
        kind = "robots"
    elif "javascript" in content_type.lower() or path.endswith((".js", ".mjs")):
        references = [(match.group(2), "javascript_literal") for match in JS_PATH.finditer(body)]
        kind = "javascript"
    seen: set[str] = set()
    candidates = []
    truncated = False
    for raw, source in references:
        if len(candidates) >= MAX_CANDIDATES:
            truncated = True
            break
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
            continue
        joined = urljoin(source_url, raw)
        parsed = urlsplit(joined)
        if parsed.scheme not in {"http", "https"}:
            continue
        if kind == "javascript" and parsed.path.lower().endswith(STATIC_SUFFIXES):
            continue
        # Values in query strings may be tokens. Keep only parameter names.
        without_query = parsed._replace(query="", fragment="").geturl()
        try:
            origin, clean_path = scope_target.web_url(without_query)
            url = origin + clean_path
            if url in seen:
                continue
            seen.add(url)
            decision = program_policy.evaluate(policy, url)
        except ValueError:
            continue
        candidates.append({"url": url, "source": source,
                           "query_keys": sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})[:20],
                           "scope_decision": decision["decision"],
                           "scope_reason": decision["reason"]})
    return {"format": kind, "title": title, "candidate_count": len(candidates),
            "candidates_truncated": truncated,
            "candidates": candidates}
