"""Body text/HTML extraction and link inventory. No rendering, no fetching.

HTML is walked with the stdlib tokenizer only: we look at tag attributes and
text nodes. Scripts and styles are ignored as text but their ``src``/``url()``
values are still harvested as indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message
from html.parser import HTMLParser

from mailtrace_core.models import UrlRecord
from mailtrace_core.parsing.attachments import is_attachment_part
from mailtrace_core.parsing.urls import build_url_record, find_urls_in_text

_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", re.IGNORECASE)
_META_REFRESH_RE = re.compile(r"url\s*=\s*['\"]?([^'\";\s]+)", re.IGNORECASE)


@dataclass(slots=True)
class TrackingPixel:
    src: str
    width: str | None
    height: str | None


@dataclass(slots=True)
class HtmlSummary:
    text: str
    links: list[tuple[str, str]]
    """(href, visible text) pairs."""
    sources: list[tuple[str, str]]
    """(url, tag) for img/iframe/script/etc."""
    form_actions: list[str]
    pixels: list[TrackingPixel]
    has_script: bool = False
    has_forms: bool = False
    hidden_text_chunks: int = 0


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.sources: list[tuple[str, str]] = []
        self.form_actions: list[str] = []
        self.pixels: list[TrackingPixel] = []
        self.has_script = False
        self.has_forms = False
        self.hidden_chunks = 0
        self._skip_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._hidden_depth = 0

    @staticmethod
    def _is_hidden(attrs: dict[str, str | None]) -> bool:
        style = (attrs.get("style") or "").replace(" ", "").lower()
        return (
            "display:none" in style
            or "visibility:hidden" in style
            or "font-size:0" in style
            or "opacity:0" in style
            or attrs.get("hidden") is not None
        )

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs_list)
        tag = tag.lower()
        if tag in {"script", "style"}:
            self._skip_depth += 1
            if tag == "script":
                self.has_script = True
                if attrs.get("src"):
                    self.sources.append((attrs["src"] or "", "script"))
            return
        if self._is_hidden(attrs):
            self._hidden_depth += 1
            self.hidden_chunks += 1
        if tag == "a" and attrs.get("href"):
            self._anchor_href = attrs["href"]
            self._anchor_text = []
        elif tag in {"img", "iframe", "frame", "embed", "source", "video", "audio", "object"}:
            src = attrs.get("src") or attrs.get("data")
            if src:
                self.sources.append((src, tag))
            if tag == "img":
                w, h = attrs.get("width"), attrs.get("height")
                if src and _is_pixel(w, h, attrs.get("style")):
                    self.pixels.append(TrackingPixel(src=src, width=w, height=h))
        elif tag == "form":
            self.has_forms = True
            if attrs.get("action"):
                self.form_actions.append(attrs["action"] or "")
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            m = _META_REFRESH_RE.search(attrs.get("content") or "")
            if m:
                self.sources.append((m.group(1), "meta-refresh"))
        elif tag == "base" and attrs.get("href"):
            self.sources.append((attrs["href"] or "", "base"))
        style = attrs.get("style")
        if style:
            for m in _CSS_URL_RE.finditer(style):
                self.sources.append((m.group(1), "css-url"))
        if tag in {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "td", "table"}:
            self.text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "a" and self._anchor_href is not None:
            self.links.append((self._anchor_href, " ".join("".join(self._anchor_text).split())))
            self._anchor_href = None
            self._anchor_text = []
        if tag in {"p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table"}:
            self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._anchor_href is not None:
            self._anchor_text.append(data)
        self.text_parts.append(data)

    def close(self) -> None:
        super().close()
        if self._anchor_href is not None:  # unclosed <a> at end of document
            self.links.append((self._anchor_href, " ".join("".join(self._anchor_text).split())))
            self._anchor_href = None


def _is_pixel(w: str | None, h: str | None, style: str | None) -> bool:
    def tiny(v: str | None) -> bool:
        if v is None:
            return False
        v = v.strip().rstrip("px").strip()
        return v in {"0", "1"}

    if tiny(w) and tiny(h):
        return True
    s = (style or "").replace(" ", "").lower()
    return ("width:1px" in s or "width:0" in s) and ("height:1px" in s or "height:0" in s)


def summarize_html(html: str) -> HtmlSummary:
    p = _Extractor()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - tolerate malformed markup; keep what we got
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.text_parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return HtmlSummary(
        text=text,
        links=p.links,
        sources=p.sources,
        form_actions=p.form_actions,
        pixels=p.pixels,
        has_script=p.has_script,
        has_forms=p.has_forms,
        hidden_text_chunks=p.hidden_chunks,
    )


@dataclass(slots=True)
class BodyExtraction:
    text: str = ""
    html: str = ""
    html_text: str = ""
    urls: list[UrlRecord] = field(default_factory=list)
    pixels: list[TrackingPixel] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    has_script: bool = False
    hidden_text_chunks: int = 0
    warnings: list[str] = field(default_factory=list)


def _decode_text_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return str(payload or "")
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_bodies(msg: Message) -> tuple[str, str]:
    """Return ``(text_plain, text_html)`` concatenating all non-attachment parts."""
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        if part.is_multipart() or is_attachment_part(part):
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            texts.append(_decode_text_part(part))
        elif ctype == "text/html":
            htmls.append(_decode_text_part(part))
    return "\n".join(texts), "\n".join(htmls)


def _is_indicator_url(u: str) -> bool:
    low = u.strip().lower()
    if not low or low.startswith(("cid:", "#", "data:image/")):
        return False
    return True


def extract_from_bodies(text: str, html: str, *, shorteners: list[str] | None = None) -> BodyExtraction:
    """Inventory URLs from plain text and HTML; dedupe on (url, source, display)."""
    out = BodyExtraction(text=text, html=html)
    seen: set[tuple[str, str, str | None]] = set()

    def add(raw: str, source: str, display: str | None = None) -> None:
        if not _is_indicator_url(raw):
            return
        rec = build_url_record(raw.strip(), source, display_text=display, shorteners=shorteners)
        key = (rec.normalized, source, display)
        if key in seen:
            return
        seen.add(key)
        out.urls.append(rec)

    for raw in find_urls_in_text(text):
        add(raw, "text")

    if html:
        summary = summarize_html(html)
        out.html_text = summary.text
        out.pixels = summary.pixels
        out.form_actions = summary.form_actions
        out.has_script = summary.has_script
        out.hidden_text_chunks = summary.hidden_text_chunks
        for href, visible in summary.links:
            if href.lower().startswith("mailto:"):
                add(href, "html-href", visible or None)
                continue
            add(href, "html-href", visible or None)
        for src, tag in summary.sources:
            add(src, f"html-src:{tag}")
        for action in summary.form_actions:
            add(action, "html-action")
        for raw in find_urls_in_text(summary.text):
            add(raw, "html-text")
        if summary.has_script:
            out.warnings.append("HTML body contains <script> (ignored, never executed)")
        if summary.has_forms:
            out.warnings.append("HTML body contains a <form> (credential capture pattern)")
        if summary.hidden_text_chunks:
            out.warnings.append(
                f"HTML body has {summary.hidden_text_chunks} hidden element(s) "
                "(filter-evasion / hidden text pattern)"
            )
    return out
