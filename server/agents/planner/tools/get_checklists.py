"""
get_checklists.py
=================
Fetch and parse OWASP checklist-style content for a given target type.

Implemented OWASP formats
-------------------------
1. OWASP WSTG checklist markdown table
2. OWASP API Security Top 10 2023 markdown pages
3. OWASP MASTG mobile chapter markdown
4. OWASP Kubernetes Top 10 markdown
5. OWASP ISTG checklist markdown (IoT)

Implemented MITRE formats
-------------------------
1. ATT&CK tactic pages
2. ATT&CK matrix pages (extract tactic links, then parse tactics)

Design goals
------------
- Minimal-token JSON output
- Future-tolerant parsing
- Preserve MITRE/PTES URLs in registry
- Deduplicate across multiple source files
- Keep OWASP and MITRE normalized but separated in output
- Keep same MITRE data while omitting per-item URLs from compact JSON
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from server.config.agent import llm_mode, local_llm_config, public_llm_config
from server.core.llm import ChatMessage, LLMClient
from server.core.tool import tool
from server.db.knowledge.config.checklist_sources import CHECKLIST_SOURCES

log = logging.getLogger(__name__)

_CHECKLIST_CLEANER_SYSTEM_PROMPT = """
You clean and normalize checklist output into strict JSON.

Return JSON only in this exact shape:
{"target_type":"...","available_total":0,"checklist":[{"phase":"1","title":"Reconnaissance","items":["..."]}]}

Rules:
- keep only security-testing checklist items
- deduplicate repeated items
- keep phases ordered from lowest to highest
- each checklist block must contain `phase`, `title`, and `items`
- each item must stay short and concrete
- do not add prose, markdown, or explanations outside the JSON
""".strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  Data models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ChecklistItem:
    """Single normalized OWASP checklist item."""

    test_id: str
    test_name: str
    category: str
    cat_name: str
    phase: str


@dataclass(slots=True)
class MitreItem:
    """Single MITRE ATT&CK technique under a tactic."""

    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    url: str


# ═══════════════════════════════════════════════════════════════════════════════
#  OWASP parser
# ═══════════════════════════════════════════════════════════════════════════════

class OWASPChecklistParser:
    _SEP_RE = re.compile(r"^[-:\s|]+$")
    _SKIP_LABELS = frozenset({"test id", "test_id", "id", "test name", "status", "notes"})

    _WSTG_ITEM_RE = re.compile(r"^(WSTG-[A-Z]+-\d+)$", re.IGNORECASE)
    _WSTG_CATEGORY_RE = re.compile(r"^\*{0,2}(WSTG-[A-Z]+)\*{0,2}$", re.IGNORECASE)

    _ISTG_ITEM_RE = re.compile(r"^(ISTG-[A-Z0-9\[\]-]+-\d{3})$", re.IGNORECASE)
    _ISTG_CATEGORY_RE = re.compile(r"^\*{0,2}(ISTG-[A-Z0-9\[\]-]+)\*{0,2}$", re.IGNORECASE)
    _ISTG_SECTION_RE = re.compile(r"^##+\s+(.+?)\s+\((ISTG-[A-Z0-9\[\]-]+)\)\s*$", re.IGNORECASE)

    _API_FILE_RE = re.compile(r"/(0x11-t10|0xa[a-f0-9-]+)\.md$", re.IGNORECASE)
    _API_TOKEN_RE = re.compile(r"\bAPI(?:10|[1-9])\s*:\s*20\d{2}\b", re.IGNORECASE)

    _MASTG_FILE_RE = re.compile(r"/0x0(?:4|5|6)[a-zA-Z0-9-]*\.md$", re.IGNORECASE)
    _H1_RE = re.compile(r"^#\s+(.+?)\s*$")
    _H2_RE = re.compile(r"^##\s+(.+?)\s*$")
    _H3_RE = re.compile(r"^###\s+(.+?)\s*$")
    _H4_RE = re.compile(r"^####\s+(.+?)\s*$")

    _K8S_FILE_RE = re.compile(
        r"/www-project-kubernetes-top-ten/.*/(?:index|K\d{2}[-A-Za-z0-9]+)\.md$",
        re.IGNORECASE,
    )
    _K8S_LIST_RE = re.compile(
        r"^\s*[-*]\s+\[K(0?\d{1,2})\s*:\s*([^\]]+)\]\([^)]+\)\s*$",
        re.IGNORECASE,
    )
    _K8S_SECTION_RE = re.compile(
        r"^##\s+Top\s+10\s+Kubernetes\s+Risks\s*-\s*(20\d{2})\s*$",
        re.IGNORECASE,
    )

    _CATEGORY_PHASE: dict[str, str] = {
        "WSTG-INFO": "1",
        "WSTG-CONF": "3",
        "WSTG-IDNT": "3",
        "WSTG-ATHN": "4",
        "WSTG-ATHZ": "4",
        "WSTG-SESS": "5",
        "WSTG-INPV": "4",
        "WSTG-ERRH": "3",
        "WSTG-CRYP": "3",
        "WSTG-BUSL": "4",
        "WSTG-CLNT": "4",
        "WSTG-APIT": "4",
        "WSTG-BUSLOGIC": "4",
        "OWASP-API-TOP10-2023": "4",
        "MASTG-MOBILE": "3",
        "MASTG-ANDROID": "4",
        "MASTG-IOS": "4",
        "OWASP-K8S-TOP10-2025": "4",
        "OWASP-K8S-TOP10-2022": "4",
        "ISTG-PROC-AUTHZ": "4",
        "ISTG-PROC-LOGIC": "4",
        "ISTG-PROC-SIDEC": "4",
        "ISTG-MEM-INFO": "1",
        "ISTG-MEM-SCRT": "5",
        "ISTG-MEM-CRYPT": "3",
        "ISTG-FW-INFO": "1",
        "ISTG-FW-CONF": "3",
        "ISTG-FW-SCRT": "5",
        "ISTG-FW-CRYPT": "3",
        "ISTG-FW[INST]-AUTHZ": "4",
        "ISTG-FW[INST]-INFO": "1",
        "ISTG-FW[INST]-CRYPT": "3",
        "ISTG-FW[UPDT]-AUTHZ": "4",
        "ISTG-FW[UPDT]-CRYPT": "3",
        "ISTG-FW[UPDT]-LOGIC": "4",
        "ISTG-DES-AUTHZ": "4",
        "ISTG-DES-INFO": "1",
        "ISTG-DES-CONF": "3",
        "ISTG-DES-SCRT": "5",
        "ISTG-DES-CRYPT": "3",
        "ISTG-DES-LOGIC": "4",
        "ISTG-DES-INPV": "4",
        "ISTG-INT-AUTHZ": "4",
        "ISTG-INT-INFO": "1",
        "ISTG-INT-CONF": "3",
        "ISTG-INT-SCRT": "5",
        "ISTG-INT-CRYPT": "3",
        "ISTG-INT-LOGIC": "4",
        "ISTG-INT-INPV": "4",
        "ISTG-PHY-AUTHZ": "4",
        "ISTG-PHY-INFO": "1",
        "ISTG-PHY-CONF": "3",
        "ISTG-PHY-SCRT": "5",
        "ISTG-PHY-CRYPT": "3",
        "ISTG-PHY-LOGIC": "4",
        "ISTG-PHY-INPV": "4",
        "ISTG-WRLS-AUTHZ": "4",
        "ISTG-WRLS-INFO": "1",
        "ISTG-WRLS-CONF": "3",
        "ISTG-WRLS-SCRT": "5",
        "ISTG-WRLS-CRYPT": "3",
        "ISTG-WRLS-LOGIC": "4",
        "ISTG-WRLS-INPV": "4",
        "ISTG-UI-AUTHZ": "4",
        "ISTG-UI-INFO": "1",
        "ISTG-UI-CONF": "3",
        "ISTG-UI-SCRT": "5",
        "ISTG-UI-CRYPT": "3",
        "ISTG-UI-LOGIC": "4",
        "ISTG-UI-INPV": "4",
    }

    _PHASE_KW: list[tuple[str, list[str]]] = [
        ("1", ["recon", "disclosure", "information gathering", "identify"]),
        ("2", ["enumeration", "fingerprint", "mapping"]),
        ("3", ["misconfig", "weak", "outdated", "configuration", "patch", "crypt", "verification"]),
        ("4", ["inject", "input validation", "authorization", "logic", "privilege escalation", "unauthorized", "command injection"]),
        ("5", ["secret", "credential", "token", "session", "confidential"]),
    ]

    PHASE_UNKNOWN = "unknown"

    _NL_RE = re.compile(r"\r\n?")
    _BLANK_RE = re.compile(r"\n{3,}")

    async def fetch_and_parse(self, url: str, *, timeout: float = 20.0) -> list[ChecklistItem]:
        content = await self._fetch(url, timeout=timeout)
        if not content:
            log.warning("Empty or failed fetch: %s", url)
            return []
        return self._parse(content, source_url=url)

    def parse_text(self, text: str, *, source_url: str = "") -> list[ChecklistItem]:
        return self._parse(text, source_url=source_url)

    @staticmethod
    def select(items: list[ChecklistItem], limit: int) -> list[ChecklistItem]:
        if len(items) <= limit:
            return list(items)

        by_cat: dict[str, list[ChecklistItem]] = {}
        for it in items:
            by_cat.setdefault(it.category, []).append(it)

        result: list[ChecklistItem] = []
        seen: set[str] = set()
        buckets = list(by_cat.values())
        idx = 0

        while len(result) < limit and buckets:
            bi = idx % len(buckets)
            bucket = buckets[bi]
            if bucket:
                item = bucket.pop(0)
                if item.test_id not in seen:
                    seen.add(item.test_id)
                    result.append(item)
                idx += 1
            else:
                buckets.pop(bi)

        return result

    def to_compact(self, items: list[ChecklistItem]) -> dict[str, Any]:
        cats: dict[str, dict[str, Any]] = {}
        for it in items:
            if it.category not in cats:
                cats[it.category] = {"n": it.cat_name, "p": it.phase, "items": []}
            cats[it.category]["items"].append([it.test_id, it.test_name])
        return {"cats": cats, "total": len(items)}

    async def _fetch(self, url: str, *, timeout: float) -> str:
        try:
            t = httpx.Timeout(timeout, connect=8.0)
            async with httpx.AsyncClient(
                timeout=t,
                headers={"User-Agent": "pentest-assistant/1.0"},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return self._clean(resp.headers.get("content-type", ""), resp.text)
        except Exception as exc:
            log.warning("fetch error [%s]: %s", url, exc)
            return ""

    def _clean(self, ct: str, body: str) -> str:
        if "html" in ct.lower() or "<html" in body[:400].lower():
            soup = BeautifulSoup(body, "html.parser")
            for t in soup(["script", "style", "noscript"]):
                t.decompose()
            body = soup.get_text("\n", strip=True)
        body = self._NL_RE.sub("\n", body.strip())
        return self._BLANK_RE.sub("\n\n", body)

    def _parse(self, text: str, *, source_url: str = "") -> list[ChecklistItem]:
        if self._looks_like_istg(text, source_url):
            log.info("Detected ISTG: %s", source_url)
            return self._parse_istg(text)
        if "WSTG-" in text and "|" in text:
            log.info("Detected WSTG: %s", source_url)
            return self._parse_wstg(text)
        if self._looks_like_api_top10(text, source_url):
            log.info("Detected API Top10: %s", source_url)
            return self._parse_api_top10(text)
        if self._looks_like_mastg(text, source_url):
            log.info("Detected MASTG: %s", source_url)
            return self._parse_mastg(text, source_url=source_url)
        if self._looks_like_k8s_top10(text, source_url):
            log.info("Detected K8s Top10: %s", source_url)
            return self._parse_k8s_top10(text)

        log.info("No parser matched: %s", source_url)
        return []

    def _looks_like_istg(self, text: str, source_url: str) -> bool:
        src = source_url.lower()
        return "owasp-istg" in src or ("ISTG-" in text and "|Test ID|Test Name|" in text)

    def _looks_like_api_top10(self, text: str, source_url: str) -> bool:
        return bool(
            self._API_FILE_RE.search(source_url)
            or "OWASP API Security Top 10" in text
            or self._API_TOKEN_RE.search(text)
        )

    def _looks_like_mastg(self, text: str, source_url: str) -> bool:
        return bool(
            self._MASTG_FILE_RE.search(source_url)
            or "Mobile Application Security Testing" in text
            or "Android Security Testing" in text
            or "iOS Security Testing" in text
            or "@MASTG-" in text
        )

    def _looks_like_k8s_top10(self, text: str, source_url: str) -> bool:
        low = text.lower()
        return bool(
            self._K8S_FILE_RE.search(source_url)
            or "owasp kubernetes top ten" in low
            or "top 10 kubernetes risks" in low
            or ("kubernetes" in low and self._K8S_LIST_RE.search(text))
        )

    def _parse_wstg(self, text: str) -> list[ChecklistItem]:
        items: list[ChecklistItem] = []
        cur_cat_name = ""

        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("|"):
                continue

            cells = [c.strip() for c in s.split("|")[1:-1]]
            if len(cells) < 2:
                continue

            c0_raw = cells[0]
            c1_raw = cells[1]
            c0 = c0_raw.strip("* ").upper()
            c1 = c1_raw.strip("* ")

            if self._SEP_RE.match(c0_raw) or c0.lower() in self._SKIP_LABELS:
                continue

            cm = self._WSTG_CATEGORY_RE.match(c0_raw)
            if cm and not self._WSTG_ITEM_RE.match(c0):
                cur_cat_name = c1
                continue

            im = self._WSTG_ITEM_RE.match(c0)
            if im and c1:
                tid = im.group(1).upper()
                icat = tid.rsplit("-", 1)[0]
                items.append(ChecklistItem(
                    test_id=tid,
                    test_name=c1,
                    category=icat,
                    cat_name=cur_cat_name,
                    phase=self._resolve_phase(icat, icat, c1),
                ))
        return items

    def _parse_istg(self, text: str) -> list[ChecklistItem]:
        items: list[ChecklistItem] = []
        cur_section_name = "OWASP IoT Security Testing Guide"
        cur_cat_name = ""

        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue

            sec = self._ISTG_SECTION_RE.match(s)
            if sec:
                cur_section_name = self._clean_heading(sec.group(1))
                cur_cat_name = ""
                continue

            if not s.startswith("|"):
                continue

            cells = [c.strip() for c in s.split("|")[1:-1]]
            if len(cells) < 2:
                continue

            c0_raw = cells[0]
            c1_raw = cells[1]
            c0 = c0_raw.strip("* ").upper()
            c1 = c1_raw.strip("* ")

            if self._SEP_RE.match(c0_raw) or c0.lower() in self._SKIP_LABELS:
                continue

            cm = self._ISTG_CATEGORY_RE.match(c0_raw)
            if cm and not self._ISTG_ITEM_RE.match(c0):
                cur_cat_name = c1 or cur_section_name
                continue

            im = self._ISTG_ITEM_RE.match(c0)
            if im and c1:
                tid = im.group(1).upper()
                icat = tid.rsplit("-", 1)[0]
                items.append(ChecklistItem(
                    test_id=tid,
                    test_name=c1,
                    category=icat,
                    cat_name=cur_cat_name or cur_section_name,
                    phase=self._resolve_phase(icat, icat, c1),
                ))

        return items

    def _parse_api_top10(self, text: str) -> list[ChecklistItem]:
        category = "OWASP-API-TOP10-2023"
        cat_name = "OWASP API Security Top 10 2023"
        found: dict[str, ChecklistItem] = {}

        for raw_line in text.splitlines():
            parsed = self._parse_api_line(raw_line)
            if not parsed:
                continue
            tid, name = parsed
            if not tid.endswith(":2023"):
                continue
            found.setdefault(tid, ChecklistItem(
                test_id=tid,
                test_name=name,
                category=category,
                cat_name=cat_name,
                phase="4",
            ))

        return sorted(found.values(), key=self._api_sort_key)

    def _parse_api_line(self, line: str) -> tuple[str, str] | None:
        s = line.strip()
        if not s:
            return None

        s = re.sub(r"^#+\s*", "", s)
        s = re.sub(r"^[-*]\s+", "", s)

        m = re.search(r"\b(API(?:10|[1-9]))\s*:\s*(20\d{2})\b", s, re.IGNORECASE)
        if not m:
            return None

        api_id = m.group(1).upper().replace(" ", "")
        year = m.group(2)
        rest = s[m.end():].strip()

        if "|" in rest:
            rest = rest.split("|", 1)[0].strip()

        rest = re.sub(r"\[[^\]]*\]\([^)]+\)", "", rest).strip()
        rest = re.sub(r"\[[^\]]+\]", "", rest).strip()
        rest = re.sub(r"\[[^\]]+\]:.*$", "", rest).strip()
        rest = re.sub(r"<[^>]+>", "", rest).strip()
        rest = re.sub(r"\s+", " ", rest).strip(" -:#\t[]")

        if not rest or len(rest) > 120 or "2019" in rest or rest.lower().startswith("owasp "):
            return None

        return (f"{api_id}:{year}", rest)

    def _parse_mastg(self, text: str, *, source_url: str = "") -> list[ChecklistItem]:
        lines = text.splitlines()
        h1 = ""
        headings: list[str] = []

        for raw in lines:
            s = raw.strip()
            if not s:
                continue

            m1 = self._H1_RE.match(s)
            if m1 and not h1:
                h1 = self._clean_heading(m1.group(1))
                continue

            for rx in (self._H2_RE, self._H3_RE, self._H4_RE):
                m = rx.match(s)
                if not m:
                    continue
                title = self._clean_heading(m.group(1))
                if self._keep_mastg_heading(title):
                    headings.append(title)
                break

        category, cat_name = self._mastg_category(source_url, h1)
        phase = self._CATEGORY_PHASE.get(category, self._resolve_phase(category, category, h1))

        seen: set[str] = set()
        items: list[ChecklistItem] = []

        for heading in headings:
            if heading in seen:
                continue
            seen.add(heading)
            items.append(ChecklistItem(
                test_id=f"{category}-{len(items)+1:02d}",
                test_name=heading,
                category=category,
                cat_name=cat_name,
                phase=phase,
            ))

        return items

    def _mastg_category(self, source_url: str, h1: str) -> tuple[str, str]:
        low = (h1 or "").lower()
        src = source_url.lower()

        if "android security testing" in low or "0x05b-" in src:
            return ("MASTG-ANDROID", "Android Security Testing")
        if "ios security testing" in low or "0x06b-" in src:
            return ("MASTG-IOS", "iOS Security Testing")
        return ("MASTG-MOBILE", h1 or "Mobile Application Security Testing")

    @staticmethod
    def _keep_mastg_heading(title: str) -> bool:
        if not title:
            return False
        low = title.lower()
        return low not in {"references", "host device", "testing device", "free emulators", "commercial emulators"} and not low.startswith(("example:", "note:"))

    def _parse_k8s_top10(self, text: str) -> list[ChecklistItem]:
        by_year: dict[str, dict[str, ChecklistItem]] = {}
        current_year: str | None = None

        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue

            sec = self._K8S_SECTION_RE.match(s)
            if sec:
                current_year = sec.group(1)
                by_year.setdefault(current_year, {})
                continue

            m = self._K8S_LIST_RE.match(s)
            if m and current_year:
                num = int(m.group(1))
                title = self._clean_heading(m.group(2))
                if not title:
                    continue

                year = current_year
                category = f"OWASP-K8S-TOP10-{year}"
                cat_name = f"OWASP Kubernetes Top 10 {year}"
                test_id = f"K{num:02d}:{year}"

                by_year.setdefault(year, {})
                by_year[year].setdefault(test_id, ChecklistItem(
                    test_id=test_id,
                    test_name=title,
                    category=category,
                    cat_name=cat_name,
                    phase="4",
                ))

        if not by_year:
            return []

        chosen_year = "2025" if "2025" in by_year else sorted(by_year.keys(), reverse=True)[0]
        return sorted(by_year[chosen_year].values(), key=self._k8s_sort_key)

    @staticmethod
    def _clean_heading(text: str) -> str:
        s = text.strip()
        s = re.sub(r"`([^`]+)`", r"\1", s)
        s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
        s = re.sub(r"\[[^\]]+\]", "", s)
        s = re.sub(r"<[^>]+>", "", s)
        s = re.sub(r"\s+", " ", s).strip(" -:#\t")
        if not s or len(s) > 120:
            return ""
        return s

    @staticmethod
    def _api_sort_key(item: ChecklistItem) -> int:
        m = re.match(r"API(\d+):\d{4}$", item.test_id, re.IGNORECASE)
        return int(m.group(1)) if m else 999

    @staticmethod
    def _k8s_sort_key(item: ChecklistItem) -> int:
        m = re.match(r"K(\d+):\d{4}$", item.test_id, re.IGNORECASE)
        return int(m.group(1)) if m else 999

    def _resolve_phase(self, item_cat: str, header_cat: str, name: str) -> str:
        p = self._CATEGORY_PHASE.get(item_cat) or self._CATEGORY_PHASE.get(header_cat)
        if p:
            return p

        low = name.lower()
        for pid, kws in self._PHASE_KW:
            if any(k in low for k in kws):
                return pid
        return self.PHASE_UNKNOWN


# ═══════════════════════════════════════════════════════════════════════════════
#  MITRE parser
# ═══════════════════════════════════════════════════════════════════════════════

class MITREAttackParser:
    """
    Parse MITRE ATT&CK tactic pages and matrix pages.

    Output:
    - tactic pages -> technique list
    - matrix pages -> tactic URLs -> fetch tactic pages
    """

    _TACTIC_URL_RE = re.compile(r"/tactics/(TA\d{4})/?$", re.IGNORECASE)
    _MATRIX_URL_RE = re.compile(r"/matrices/", re.IGNORECASE)
    _TECH_ID_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
    _TECH_URL_RE = re.compile(r"/techniques/(T\d{4})(?:/(\d{3}))?/?", re.IGNORECASE)

    async def fetch_and_parse(self, url: str, *, timeout: float = 20.0) -> list[MitreItem]:
        html = await self._fetch(url, timeout=timeout)
        if not html:
            return []

        if self._TACTIC_URL_RE.search(url):
            return self._parse_tactic_page(html, source_url=url)

        if self._MATRIX_URL_RE.search(url):
            tactic_urls = self._parse_matrix_for_tactic_urls(html, source_url=url)
            if not tactic_urls:
                return []
            return await self._fetch_tactics(tactic_urls, timeout=timeout)

        return []

    async def _fetch_tactics(self, urls: list[str], *, timeout: float) -> list[MitreItem]:
        async def _one(url: str) -> list[MitreItem]:
            html = await self._fetch(url, timeout=timeout)
            if not html:
                return []
            return self._parse_tactic_page(html, source_url=url)

        results = await asyncio.gather(*(_one(url) for url in urls), return_exceptions=True)
        merged: dict[tuple[str, str], MitreItem] = {}

        for result in results:
            if isinstance(result, Exception):
                log.warning("MITRE tactic fetch error: %s", result)
                continue
            for item in result:
                merged.setdefault((item.tactic_id, item.technique_id), item)

        return sorted(merged.values(), key=lambda x: (x.tactic_id, x.technique_id))

    async def _fetch(self, url: str, *, timeout: float) -> str:
        try:
            t = httpx.Timeout(timeout, connect=8.0)
            async with httpx.AsyncClient(
                timeout=t,
                headers={"User-Agent": "pentest-assistant/1.0"},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.text
        except Exception as exc:
            log.warning("MITRE fetch error [%s]: %s", url, exc)
            return ""

    def _parse_matrix_for_tactic_urls(self, html: str, *, source_url: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        out: list[str] = []
        seen: set[str] = set()

        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if not href or not self._TACTIC_URL_RE.search(href):
                continue
            abs_url = urljoin(source_url, href)
            if abs_url not in seen:
                seen.add(abs_url)
                out.append(abs_url)

        return out

    def _parse_tactic_page(self, html: str, *, source_url: str) -> list[MitreItem]:
        soup = BeautifulSoup(html, "html.parser")
        tactic_id = self._extract_tactic_id(source_url)
        tactic_name = self._extract_tactic_name(soup) or tactic_id
        found: dict[str, MitreItem] = {}

        # Prefer row-based parsing for cleaner sub-technique names.
        for tr in soup.find_all("tr"):
            links = []
            for a in tr.find_all("a", href=True):
                href = a.get("href", "").strip()
                if "/techniques/" not in href:
                    continue
                tech_id = self._extract_technique_id(href)
                if not tech_id:
                    continue
                links.append((a, href, tech_id))

            if not links:
                continue

            cells = [self._clean_text(td.get_text(" ", strip=True)) for td in tr.find_all(["td", "th"])]
            row_texts = [c for c in cells if c]

            for a, href, tech_id in links:
                tech_url = urljoin(source_url, href)
                tech_name = self._best_name_for_technique(
                    tech_id=tech_id,
                    anchor_text=self._clean_text(a.get_text(" ", strip=True)),
                    row_texts=row_texts,
                )
                found.setdefault(
                    tech_id.upper(),
                    MitreItem(
                        tactic_id=tactic_id,
                        tactic_name=tactic_name,
                        technique_id=tech_id.upper(),
                        technique_name=tech_name,
                        url=tech_url,
                    ),
                )

        # Fallback: if row parsing missed anything, scan anchors
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if "/techniques/" not in href:
                continue

            tech_url = urljoin(source_url, href)
            tech_id = self._extract_technique_id(href)
            if not tech_id or tech_id.upper() in found:
                continue

            anchor_text = self._clean_text(a.get_text(" ", strip=True))
            tech_name = anchor_text if self._is_good_tech_name(anchor_text, tech_id) else tech_id

            found.setdefault(
                tech_id.upper(),
                MitreItem(
                    tactic_id=tactic_id,
                    tactic_name=tactic_name,
                    technique_id=tech_id.upper(),
                    technique_name=tech_name,
                    url=tech_url,
                ),
            )

        return sorted(found.values(), key=lambda x: x.technique_id)

    def _best_name_for_technique(
        self,
        *,
        tech_id: str,
        anchor_text: str,
        row_texts: list[str],
    ) -> str:
        if self._is_good_tech_name(anchor_text, tech_id):
            return anchor_text

        # Prefer the first meaningful row text that is not just the technique ID or suffix.
        for txt in row_texts:
            if self._is_good_tech_name(txt, tech_id):
                return txt

        # Sometimes rows contain the parent and sub-technique names separately; prefer longer text.
        candidates = [txt for txt in row_texts if txt and not self._looks_like_id_or_suffix(txt)]
        if candidates:
            candidates.sort(key=len, reverse=True)
            return candidates[0]

        return tech_id

    def _is_good_tech_name(self, text: str, tech_id: str) -> bool:
        txt = self._clean_text(text)
        if not txt:
            return False

        if txt.upper() == tech_id.upper():
            return False

        if self._looks_like_id_or_suffix(txt):
            return False

        # Reject pure ATT&CK ids embedded as text.
        if self._TECH_ID_RE.match(txt):
            return False

        return True

    @staticmethod
    def _looks_like_id_or_suffix(text: str) -> bool:
        low = text.strip().lower()
        if re.fullmatch(r"\.\d{3}", low):
            return True
        if re.fullmatch(r"t\d{4}(?:\.\d{3})?", low):
            return True
        return False

    def _extract_tactic_id(self, source_url: str) -> str:
        m = self._TACTIC_URL_RE.search(source_url)
        return m.group(1).upper() if m else "UNKNOWN"

    @staticmethod
    def _extract_tactic_name(soup: BeautifulSoup) -> str:
        h1 = soup.find("h1")
        if h1:
            text = re.sub(r"\s+", " ", h1.get_text(" ", strip=True)).strip()
            if text:
                return text

        title = soup.find("title")
        if title:
            text = re.sub(r"\s+", " ", title.get_text(" ", strip=True)).strip()
            text = re.sub(r"\s*-\s*.*$", "", text)
            if text:
                return text

        return ""

    def _extract_technique_id(self, text: str) -> str:
        m = self._TECH_URL_RE.search(text)
        if not m:
            return ""
        base = m.group(1).upper()
        sub = m.group(2)
        return f"{base}.{sub}" if sub else base

    @staticmethod
    def _clean_text(text: str) -> str:
        return re.sub(r"\s+", " ", (text or "").strip())[:160].strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  Target resolution + filters
# ═══════════════════════════════════════════════════════════════════════════════

_ALIASES: dict[str, str] = {
    "web_app": "web_app",
    "web": "web_app",
    "web_application": "web_app",
    "api": "api",
    "mobile": "mobile",
    "mobile_app": "mobile",
    "network": "network",
    "iot": "iot",
    "linux_server": "linux_server",
    "linux": "linux_server",
    "server": "linux_server",
    "infra": "infra",
    "infrastructure": "infra",
    "desktop": "desktop",
    "desktop_app": "desktop",
    "desktop_application": "desktop",
    "cloud": "cloud",
    "container": "container",
    "database": "infra",
    "db": "infra",
    "repository": "repository",
    "repo": "repository",
}

_PROFILE: dict[str, str] = {
    "web_app": "web",
    "api": "api",
    "mobile": "mobile",
    "network": "network",
    "iot": "iot",
    "linux_server": "linux_server",
    "infra": "infra",
    "desktop": "web",
    "cloud": "cloud",
    "container": "container",
    "repository": "repository",
}

_RAG: dict[str, str] = {
    "infra": "linux_server",
    "container": "cloud",
    "repository": "linux_server",
}

_REPO_KEEP_IDS = frozenset({
    "WSTG-INFO-01",
    "WSTG-INFO-03",
    "WSTG-INFO-05",
    "WSTG-CONF-03",
    "WSTG-CONF-04",
    "WSTG-CONF-05",
    "WSTG-CONF-09",
    "WSTG-ATHN-02",
    "WSTG-ATHN-07",
    "WSTG-ATHN-09",
    "WSTG-ATHZ-02",
    "WSTG-ATHZ-03",
    "WSTG-ATHZ-04",
    "WSTG-CRYP-03",
    "WSTG-CRYP-04",
    "WSTG-ERRH-01",
    "WSTG-ERRH-02",
    "WSTG-IDNT-04",
    "WSTG-IDNT-05",
    "WSTG-SESS-10",
})
_REPO_KEEP_KW = (
    "credential", "secret", "token", "password", "source code", "repository",
    "repo", "disclosure", "information leakage", "backup", "unreferenced files",
    "admin interfaces", "git", "jwt",
)
_REPO_EXCLUDE_KW = (
    "xss", "cross site", "cross-site", "css injection", "clickjacking", "websocket",
    "web messaging", "browser", "dom ", "flash", "graphql", "csrf", "cors",
    "host header", "template injection", "ssrf", "oauth weaknesses",
    "directory traversal file include",
)

_LINUX_KEEP_IDS = frozenset({
    "WSTG-INFO-03",
    "WSTG-INFO-04",
    "WSTG-CONF-01",
    "WSTG-CONF-02",
    "WSTG-CONF-03",
    "WSTG-CONF-04",
    "WSTG-CONF-05",
    "WSTG-CONF-06",
    "WSTG-CONF-09",
    "WSTG-ATHN-02",
    "WSTG-ATHN-07",
    "WSTG-ATHN-09",
    "WSTG-ATHZ-02",
    "WSTG-ATHZ-03",
    "WSTG-CRYP-03",
    "WSTG-CRYP-04",
    "WSTG-ERRH-01",
    "WSTG-ERRH-02",
    "WSTG-IDNT-04",
    "WSTG-IDNT-05",
    "WSTG-INPV-11",
    "WSTG-INPV-12",
    "WSTG-INPV-13",
})
_LINUX_KEEP_KW = (
    "default credentials", "weak password", "password change", "authorization schema",
    "privilege escalation", "network infrastructure", "application platform configuration",
    "backup", "unreferenced files", "admin interfaces", "file permission",
    "sensitive information", "cryptographic", "stack traces", "improper error handling",
    "code injection", "command injection", "format string",
)
_LINUX_EXCLUDE_KW = (
    "xss", "cross site", "cross-site", "css injection", "clickjacking", "websocket",
    "web messaging", "browser", "dom ", "flash", "graphql", "csrf", "cors",
    "host header", "template injection", "ssrf",
)

_CONTAINER_KEEP_KW = (
    "cluster", "cloud", "storage", "misconfig", "configuration",
    "secrets", "workload", "network", "authorization", "authentication",
)


def _norm(t: str) -> str:
    k = (t or "").strip().lower().replace("-", "_")
    r = _ALIASES.get(k)
    if r is None:
        log.warning("Unknown target '%s' → 'web_app'", t)
        return "web_app"
    return r


def _normalize_target_type(value: str) -> str:
    return _norm(value)


def _rag_domain_for_target(target_type: str) -> str:
    return _RAG.get(_norm(target_type), _norm(target_type))


def _checklist_profile_for_target(target_type: str) -> str:
    return _PROFILE.get(_norm(target_type), "web")


async def _collect_from_urls(
    parser: OWASPChecklistParser,
    urls: list[str],
) -> tuple[list[str], dict[tuple[str, str], ChecklistItem]]:
    merged: dict[tuple[str, str], ChecklistItem] = {}
    successful_urls: list[str] = []

    async def _fetch_one(url: str) -> tuple[str, list[ChecklistItem]]:
        items = await parser.fetch_and_parse(url)
        return url, items

    results = await asyncio.gather(*(_fetch_one(url) for url in urls), return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            log.warning("collect error: %s", result)
            continue
        url, items = result
        if not items:
            continue
        successful_urls.append(url)
        for item in items:
            merged.setdefault((item.category, item.test_id), item)

    return successful_urls, merged


async def _collect_mitre_from_urls(
    parser: MITREAttackParser,
    urls: list[str],
) -> list[MitreItem]:
    results = await asyncio.gather(*(parser.fetch_and_parse(url) for url in urls), return_exceptions=True)
    merged: dict[tuple[str, str], MitreItem] = {}

    for result in results:
        if isinstance(result, Exception):
            log.warning("MITRE collect error: %s", result)
            continue
        for item in result:
            merged.setdefault((item.tactic_id, item.technique_id), item)

    return sorted(merged.values(), key=lambda x: (x.tactic_id, x.technique_id))


def _filter_for_target(target: str, items: list[ChecklistItem]) -> list[ChecklistItem]:
    if target == "repository":
        out = []
        for it in items:
            low = f"{it.test_id} {it.test_name} {it.category} {it.cat_name}".lower()
            if any(x in low for x in _REPO_EXCLUDE_KW):
                continue
            if it.test_id in _REPO_KEEP_IDS or any(k in low for k in _REPO_KEEP_KW):
                out.append(it)
        return out

    if target == "linux_server":
        out = []
        for it in items:
            low = f"{it.test_id} {it.test_name} {it.category} {it.cat_name}".lower()
            if any(x in low for x in _LINUX_EXCLUDE_KW):
                continue
            if it.test_id in _LINUX_KEEP_IDS or any(k in low for k in _LINUX_KEEP_KW):
                out.append(it)
        return out

    if target == "container":
        out = []
        for it in items:
            low = f"{it.test_id} {it.test_name} {it.category} {it.cat_name}".lower()
            if it.category.startswith("OWASP-K8S-TOP10-") or any(k in low for k in _CONTAINER_KEEP_KW):
                out.append(it)
        return out

    return items


def _sort_items(parser: OWASPChecklistParser, target: str, items: list[ChecklistItem]) -> None:
    if target == "api":
        items.sort(key=lambda x: parser._api_sort_key(x))
    else:
        items.sort(key=lambda x: (x.category, x.test_id))


def _mitre_to_compact(items: list[MitreItem]) -> dict[str, Any]:
    tactics: dict[str, dict[str, Any]] = {}
    for it in items:
        if it.tactic_id not in tactics:
            tactics[it.tactic_id] = {"n": it.tactic_name, "items": []}
        tactics[it.tactic_id]["items"].append([it.technique_id, it.technique_name])
    return {"tactics": tactics, "total": len(items)}



def _phase_sort_key(phase: str) -> int:
    try:
        return int(str(phase).strip())
    except Exception:
        return 99


def _normalize_phase_value(phase: str, title: str = "") -> str:
    raw_phase = str(phase or "").strip()
    if raw_phase in {"1", "2", "3", "4", "5", "6", "7", "8"}:
        return raw_phase

    match = re.search(r"\b([1-8])\b", raw_phase)
    if match:
        return match.group(1)

    lowered_title = str(title or "").lower()
    if "recon" in lowered_title:
        return "1"
    if "enumeration" in lowered_title or "mapping" in lowered_title:
        return "2"
    if "configuration" in lowered_title:
        return "3"
    if "authentication" in lowered_title or "authorization" in lowered_title or "injection" in lowered_title:
        return "4"
    if "session" in lowered_title:
        return "5"
    if "exploitation" in lowered_title or "validation" in lowered_title:
        return "6"
    if "post-exploitation" in lowered_title or "post exploitation" in lowered_title:
        return "7"
    if "report" in lowered_title:
        return "8"
    return raw_phase or "unknown"


def _clamp_priority(value: Any, default: int) -> int:
    try:
        numeric = int(value)
    except Exception:
        return max(1, min(5, int(default)))
    return max(1, min(5, numeric))


def _default_priority_for_item(name: str, phase: str) -> int:
    """Assign priority based on industry-standard severity scale.

    Priority scale (lower = more severe):
      P1 = Critical -> SQLi, RCE, SSRF, Command Injection, IDOR, PrivEsc
      P2 = High     -> XSS, SSTI, Auth Bypass, Directory Traversal, GraphQL
      P3 = Medium   -> TLS, Headers, Config, Error Handling, Session
      P4 = Low      -> Info leakage, clickjacking, cache weakness
      P5 = Info     -> Fingerprinting, recon, enumeration items
    """
    title = str(name or "").lower()
    phase_str = str(phase or "").strip()

    # P1 = Critical
    if any(
        needle in title
        for needle in (
            "sql injection",
            "command injection",
            "code injection",
            "server-side request forgery",
            "ssrf",
            "insecure direct object references",
            "idor",
            "privilege escalation",
            "default credentials",
            "upload of malicious files",
            "broken object level authorization",
            "bypassing authorization schema",
            "remote code execution",
            "rce",
            "deserialization",
        )
    ):
        return 1

    # P2 = High
    if any(
        needle in title
        for needle in (
            "xss",
            "cross site scripting",
            "directory traversal",
            "path traversal",
            "oauth",
            "graphql",
            "ssti",
            "server-side template injection",
            "authentication bypass",
            "broken authentication",
            "broken function level authorization",
        )
    ):
        return 2

    # P3 = Medium — config, headers, session, TLS
    if any(
        needle in title
        for needle in (
            "tls",
            "ssl",
            "security headers",
            "error handling",
            "session",
            "configuration",
            "misconfiguration",
            "cors",
            "content security policy",
            "cache",
        )
    ):
        return 3

    # P4 = Low — info leakage, minor issues
    if any(
        needle in title
        for needle in (
            "information disclosure",
            "information leakage",
            "clickjacking",
            "sensitive data",
            "verbose error",
        )
    ):
        return 4

    # Phase-based defaults:
    # Exploitation/Post-Exploitation phases → default P2-P3
    if phase_str in {"6", "7"}:
        return 2
    # Auth/Injection phase → default P2
    if phase_str == "4":
        return 2
    # Config/Session phases → default P3
    if phase_str in {"3", "5"}:
        return 3
    # Recon/Enumeration phases → default P5 (informational)
    if phase_str in {"1", "2"}:
        return 5
    # Reporting phase → default P4
    if phase_str == "8":
        return 4

    # Fallback: medium priority
    return 3


def _phase_block_title(phase: str) -> str:
    return {
        "1": "Reconnaissance",
        "2": "Enumeration",
        "3": "Configuration & Infrastructure Testing",
        "4": "Authentication, Authorization & Injection Testing",
        "5": "Session Management Testing",
        "6": "Exploitation & Validation",
        "7": "Post-Exploitation",
        "8": "Reporting",
    }.get(str(phase).strip(), f"Phase {phase or 'unknown'}")


def build_deterministic_checklist_payload(checklist_data: dict[str, Any], info: str) -> dict[str, Any]:
    _ = info
    cats = checklist_data.get("cats", {})
    available_total = int(checklist_data.get("available_total", checklist_data.get("total", 0)) or 0)

    phase_map: dict[str, dict[str, int]] = {}

    if isinstance(cats, dict):
        for _, cat_data in cats.items():
            if not isinstance(cat_data, dict):
                continue
            phase = _normalize_phase_value(
                str(cat_data.get("p", "unknown")),
                str(cat_data.get("n", cat_data.get("title", ""))),
            )
            items = cat_data.get("items", [])
            if not isinstance(items, list):
                continue
            for row in items:
                if not isinstance(row, list) or len(row) < 2:
                    continue
                name = str(row[1]).strip()
                if not name:
                    continue
                bucket = phase_map.setdefault(phase, {})
                default_priority = _default_priority_for_item(name, phase)
                if name not in bucket:
                    bucket[name] = default_priority
                else:
                    bucket[name] = max(bucket[name], default_priority)

    checklist_blocks = [
        {
            "phase": phase,
            "title": _phase_block_title(phase),
            "items": [
                item_name
                for item_name, item_priority in sorted(
                    phase_map[phase].items(),
                    key=lambda kv: (-kv[1], kv[0].lower()),
                )
            ],
        }
        for phase in sorted(phase_map.keys(), key=_phase_sort_key)
    ]

    return {
        "target_type": checklist_data.get("t", ""),
        "available_total": available_total,
        "checklist": checklist_blocks,
    }


def build_checklist_llm_input(checklist_data: dict[str, Any], info: str) -> str:
    payload = build_deterministic_checklist_payload(checklist_data, info)
    lines = [
        f"Target type: {payload.get('target_type', '')}",
        f"Target info: {info or 'none'}",
        f"Available checklist items: {payload.get('available_total', 0)}",
        "",
        "Return JSON in this exact shape:",
        '{"target_type":"...","available_total":0,"checklist":[{"phase":"1","title":"Reconnaissance","items":["..."]}]}',
        "",
        "Candidate checklist blocks:",
    ]
    for block in payload.get("checklist", []):
        if not isinstance(block, dict):
            continue
        phase = str(block.get("phase", ""))
        title = str(block.get("title", "")).strip()
        lines.append(f"Phase {phase} - {title}")
        for item in block.get("items", []):
            if isinstance(item, dict):
                item_name = str(item.get("name", "")).strip()
                if item_name:
                    lines.append(f"- {item_name}")
            elif isinstance(item, str):
                clean = item.strip()
                if clean:
                    lines.append(f"- {clean}")
        lines.append("")
    return "\n".join(lines).strip()


def _extract_json_object_at(text: str, start_idx: int) -> str | None:
    if start_idx < 0 or start_idx >= len(text) or text[start_idx] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for idx in range(start_idx, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_idx : idx + 1]
    return None


def _parse_checklist_json_best_effort(raw: str) -> dict[str, Any] | None:
    text = re.sub(r"<think>.*?</think>", "", str(raw or ""), flags=re.DOTALL).strip()
    if not text:
        return None

    candidate = text
    for _ in range(3):
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            break
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
            return parsed[0]
        if isinstance(parsed, str):
            next_candidate = parsed.strip()
            if not next_candidate or next_candidate == candidate:
                break
            candidate = next_candidate
            continue
        break

    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE):
        candidate = block.strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            continue

    first_brace = text.find("{")
    if first_brace >= 0:
        obj_text = _extract_json_object_at(text, first_brace)
        if obj_text:
            try:
                parsed = json.loads(obj_text)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass

    for marker in ('"checklist"', '"phase_blocks"'):
        marker_idx = text.find(marker)
        if marker_idx < 0:
            continue
        start = text.rfind("{", 0, marker_idx)
        while start >= 0:
            obj_text = _extract_json_object_at(text, start)
            if not obj_text:
                break
            try:
                parsed = json.loads(obj_text)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            start = text.rfind("{", 0, start)
    return None


def _normalize_cleaned_checklist_payload(
    parsed: dict[str, Any] | None,
    fallback_payload: dict[str, Any],
    target_type: str,
) -> dict[str, Any] | None:
    if not isinstance(parsed, dict):
        return None

    checklist_blocks: list[dict[str, Any]] = []
    raw_blocks = parsed.get("checklist", parsed.get("phase_blocks", []))
    if not isinstance(raw_blocks, list):
        raw_blocks = []
    for block in raw_blocks:
        if not isinstance(block, dict):
            continue
        title = str(block.get("title", "")).strip()
        phase = _normalize_phase_value(str(block.get("phase", "")), title)
        raw_items = block.get("items", [])
        items_by_name: dict[str, int] = {}
        if isinstance(raw_items, list):
            for item in raw_items:
                if isinstance(item, str):
                    name = str(item).strip()
                    if name:
                        items_by_name[name] = max(
                            items_by_name.get(name, 0),
                            _default_priority_for_item(name, phase),
                        )
                    continue
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", item.get("title", ""))).strip()
                if name:
                    items_by_name[name] = max(
                        items_by_name.get(name, 0),
                        _clamp_priority(
                            item.get("priority", item.get("rank", item.get("severity", 3))),
                            default=_default_priority_for_item(name, phase),
                        ),
                    )
        if phase and title and items_by_name:
            checklist_blocks.append(
                {
                    "phase": phase,
                    "title": title,
                    "items": [
                        item_name
                        for item_name, item_priority in sorted(
                            items_by_name.items(),
                            key=lambda kv: (-kv[1], kv[0].lower()),
                        )
                    ],
                }
            )

    normalized = {
        "target_type": str(parsed.get("target_type") or fallback_payload.get("target_type") or target_type),
        "available_total": int(parsed.get("available_total", fallback_payload.get("available_total", 0)) or 0),
        "checklist": checklist_blocks or fallback_payload.get("checklist", []),
    }
    return normalized


async def clean_checklists_with_llm(
    *,
    checklist_data: dict[str, Any],
    target_type: str,
    info: str,
    llm: Any | None = None,
) -> str:
    fallback_payload = build_deterministic_checklist_payload(checklist_data, info)
    llm_input = build_checklist_llm_input(checklist_data, info)

    own_client = False
    client = llm
    if client is None:
        mode = (llm_mode.mode or "local").strip().lower()
        client_mode = "local" if mode == "local" else "public"
        config = local_llm_config if client_mode == "local" else public_llm_config
        client = LLMClient(config, mode=client_mode)
        own_client = True

    try:
        response = await client.chat(
            messages=[
                ChatMessage(role="system", content=_CHECKLIST_CLEANER_SYSTEM_PROMPT),
                ChatMessage(role="user", content=llm_input),
            ],
            temperature=0.1,
            max_tokens=3000,
            use_config_max_tokens=False,
        )
        parsed = _parse_checklist_json_best_effort(str(response.content or ""))
        normalized = _normalize_cleaned_checklist_payload(parsed, fallback_payload, target_type)
        if normalized is not None:
            return json.dumps(normalized, ensure_ascii=True)
        log.warning("checklist_llm_clean_parse_failed target_type=%s", target_type)
    except Exception as exc:
        log.warning("checklist_llm_clean_failed target_type=%s error=%s", target_type, str(exc))
    finally:
        if own_client and isinstance(client, LLMClient):
            await client.close()

    return json.dumps(fallback_payload, ensure_ascii=True)


@tool(
    name="get_checklists",
    description=(
        "Fetch checklist resources by target type and return normalized OWASP checklist data "
        "plus MITRE ATT&CK tactic/technique references."
    ),
)
async def get_checklists(target_type: str, n_items: int = 0, info: str = "") -> str:
    return await _get_checklists_impl(target_type=target_type, n_items=n_items, info=info)


async def _get_checklists_impl(target_type: str, n_items: int = 0, info: str = "") -> str:
    target = _norm(target_type)

    custom_checklist_text = ""
    if info and "Operator-supplied custom checklist text:\n" in info:
        parts = info.split("Operator-supplied custom checklist text:\n")
        if len(parts) > 1:
            custom_checklist_text = parts[1].split("\n\nChecklist generation task:")[0].strip()

    if custom_checklist_text:
        from server.nodes.intel.helpers import _parse_custom_checklist_text
        parsed_custom = _parse_custom_checklist_text(custom_checklist_text, target_type=target)
        return json.dumps({
            "t": target,
            "src": "user_custom_checklist",
            "ok": True,
            "available_total": parsed_custom.get("available_total", 0),
            "checklist": parsed_custom.get("checklist", []),
            "mitre": {"tactics": {}, "total": 0},
            "mitre_urls": [],
            "ptes_urls": [],
        }, ensure_ascii=False, separators=(",", ":"))

    profile = _PROFILE.get(target, "web")
    sources = CHECKLIST_SOURCES.get(profile, CHECKLIST_SOURCES["web"])

    owasp_urls = sources.get("owasp", [])
    mitre_urls = sources.get("mitre", [])
    ptes_urls = sources.get("ptes", [])

    parser = OWASPChecklistParser()
    mitre_parser = MITREAttackParser()

    if owasp_urls:
        successful_urls, merged = await _collect_from_urls(parser, owasp_urls)
        all_items = list(merged.values())
        all_items = _filter_for_target(target, all_items)
        _sort_items(parser, target, all_items)
        available_total = len(all_items)
        limit = n_items if n_items > 0 else len(all_items)
        selected = parser.select(all_items, limit)
        compact = parser.to_compact(selected)
    else:
        successful_urls = []
        available_total = 0
        selected = []
        compact = {"cats": {}, "total": 0}

    mitre_items = await _collect_mitre_from_urls(mitre_parser, mitre_urls) if mitre_urls else []
    mitre_compact = _mitre_to_compact(mitre_items)

    return json.dumps({
        "t": target,
        "src": successful_urls if len(successful_urls) != 1 else successful_urls[0],
        "ok": len(selected) > 0,
        "available_total": available_total,
        **compact,
        "mitre": mitre_compact,
        "mitre_urls": mitre_urls,
        "ptes_urls": ptes_urls,
    }, ensure_ascii=False, separators=(",", ":"))


_ALL = [
    "web_app", "api", "mobile", "network", "iot",
    "linux_server", "infra", "desktop", "cloud", "container", "repository",
]
