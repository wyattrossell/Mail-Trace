"""Visual delivery-route diagram, rendered as SVG (HTML) or a ReportLab Drawing (PDF).

Both outputs come from one layout so they always agree. Boxes are the mail
servers from the Received chain; the first box is the origin as claimed by
the earliest header, the last is the recipient mailbox. Trusted hops are
drawn solid, unverified hops dashed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mailtrace_core.models import Hop
from mailtrace_core.util.defang import defang_ip

BOX_W, BOX_H, GAP, ROW_H, PAD = 150, 54, 34, 84, 10
PER_ROW = 4


@dataclass(slots=True)
class Node:
    x: float
    y: float
    title: str
    subtitle: str
    detail: str
    trusted: bool
    kind: str  # origin | hop | mailbox


def _nodes(hops: list[Hop], recipient: str | None) -> list[Node]:
    items: list[tuple[str, str, str, bool, str]] = []
    if hops:
        first = hops[0]
        items.append(
            (
                first.from_host or first.from_helo or "unknown host",
                defang_ip(first.from_ip) if first.from_ip else "no IP recorded",
                "claimed origin (earliest header)",
                first.trusted,
                "origin",
            )
        )
        for h in hops:
            ts = h.timestamp.strftime("%Y-%m-%d %H:%M:%S%z") if h.timestamp else "no timestamp"
            delay = (
                f"  +{h.delay_seconds:.0f}s"
                if h.delay_seconds is not None and h.delay_seconds >= 0
                else (f"  {h.delay_seconds:.0f}s" if h.delay_seconds is not None else "")
            )
            items.append(
                (
                    h.by_host or "unknown server",
                    ts + delay,
                    f"hop {h.index} via {h.protocol or '?'}",
                    h.trusted,
                    "hop",
                )
            )
    items.append((recipient or "recipient mailbox", "", "final delivery", True, "mailbox"))
    nodes: list[Node] = []
    for i, (t, s, d, tr, k) in enumerate(items):
        row, col = divmod(i, PER_ROW)
        if row % 2 == 1:  # snake layout so arrows stay short
            col = PER_ROW - 1 - col
        nodes.append(Node(PAD + col * (BOX_W + GAP), PAD + row * ROW_H, t, s, d, tr, k))
    return nodes


def _size(nodes: list[Node]) -> tuple[float, float]:
    rows = (len(nodes) + PER_ROW - 1) // PER_ROW
    cols = min(len(nodes), PER_ROW)
    return PAD * 2 + cols * BOX_W + (cols - 1) * GAP, PAD * 2 + rows * ROW_H - (ROW_H - BOX_H)


def _trim(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def route_svg(hops: list[Hop], recipient: str | None = None, dark: bool = False) -> str:
    nodes = _nodes(hops, recipient)
    w, h = _size(nodes)
    ink = "#e4e7ec" if dark else "#1c2128"
    muted = "#8f97a6" if dark else "#5f6877"
    trusted_fill = "#1c2a22" if dark else "#e9f6ee"
    untrusted_fill = "#2a2320" if dark else "#fff3e6"
    trusted_stroke = "#3ecf8e" if dark else "#1b8a4c"
    untrusted_stroke = "#f5a524" if dark else "#b26a00"
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'font-family="Segoe UI, Arial, sans-serif" font-size="11">'
    ]
    parts.append(
        '<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
        f'<path d="M0,0 L8,4 L0,8 z" fill="{muted}"/></marker></defs>'
    )
    for a, b in zip(nodes, nodes[1:], strict=False):
        if abs(a.y - b.y) < 1:
            x1, x2 = (a.x + BOX_W, b.x) if b.x > a.x else (a.x, b.x + BOX_W)
            parts.append(
                f'<line x1="{x1}" y1="{a.y + BOX_H / 2}" x2="{x2}" y2="{b.y + BOX_H / 2}" '
                f'stroke="{muted}" stroke-width="1.5" marker-end="url(#arr)"/>'
            )
        else:
            parts.append(
                f'<line x1="{a.x + BOX_W / 2}" y1="{a.y + BOX_H}" x2="{b.x + BOX_W / 2}" y2="{b.y}" '
                f'stroke="{muted}" stroke-width="1.5" marker-end="url(#arr)"/>'
            )
    for n in nodes:
        fill = trusted_fill if n.trusted else untrusted_fill
        stroke = trusted_stroke if n.trusted else untrusted_stroke
        dash = "" if n.trusted else ' stroke-dasharray="5,3"'
        parts.append(
            f'<rect x="{n.x}" y="{n.y}" width="{BOX_W}" height="{BOX_H}" rx="6" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="1.5"{dash}/>'
        )
        parts.append(
            f'<text x="{n.x + 8}" y="{n.y + 17}" fill="{ink}" font-weight="600">{_esc(_trim(n.title, 24))}</text>'
        )
        parts.append(
            f'<text x="{n.x + 8}" y="{n.y + 32}" fill="{ink}" font-size="10">{_esc(_trim(n.subtitle, 27))}</text>'
        )
        parts.append(
            f'<text x="{n.x + 8}" y="{n.y + 46}" fill="{muted}" font-size="9">{_esc(_trim(n.detail, 30))}'
            f"{'' if n.trusted else ' (unverified)'}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def route_drawing(hops: list[Hop], recipient: str | None = None, max_width: float | None = None) -> Any:
    """ReportLab ``Drawing`` for the PDF, scaled to ``max_width`` points if given."""
    from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
    from reportlab.lib import colors

    nodes = _nodes(hops, recipient)
    w, h = _size(nodes)
    d = Drawing(w, h)
    muted = colors.HexColor("#5f6877")

    def flip(y: float) -> float:  # SVG y-down -> PDF y-up
        return h - y

    for a, b in zip(nodes, nodes[1:], strict=False):
        if abs(a.y - b.y) < 1:
            x1, x2 = (a.x + BOX_W, b.x) if b.x > a.x else (a.x, b.x + BOX_W)
            y = flip(a.y + BOX_H / 2)
            d.add(Line(x1, y, x2, y, strokeColor=muted, strokeWidth=1.2))
            direction = 1 if x2 > x1 else -1
            d.add(
                Polygon(
                    [x2, y, x2 - 7 * direction, y + 3.5, x2 - 7 * direction, y - 3.5],
                    fillColor=muted,
                    strokeColor=muted,
                )
            )
        else:
            x1, y1, x2, y2 = a.x + BOX_W / 2, flip(a.y + BOX_H), b.x + BOX_W / 2, flip(b.y)
            d.add(Line(x1, y1, x2, y2, strokeColor=muted, strokeWidth=1.2))
            d.add(Polygon([x2, y2, x2 - 3.5, y2 + 7, x2 + 3.5, y2 + 7], fillColor=muted, strokeColor=muted))
    for n in nodes:
        fill = colors.HexColor("#e9f6ee") if n.trusted else colors.HexColor("#fff3e6")
        stroke = colors.HexColor("#1b8a4c") if n.trusted else colors.HexColor("#b26a00")
        r = Rect(
            n.x,
            flip(n.y + BOX_H),
            BOX_W,
            BOX_H,
            rx=6,
            ry=6,
            fillColor=fill,
            strokeColor=stroke,
            strokeWidth=1.2,
        )
        if not n.trusted:
            r.strokeDashArray = [4, 2]
        d.add(r)
        d.add(String(n.x + 8, flip(n.y + 17), _trim(n.title, 24), fontName="Helvetica-Bold", fontSize=9))
        d.add(String(n.x + 8, flip(n.y + 32), _trim(n.subtitle, 30), fontName="Helvetica", fontSize=8))
        tail = "" if n.trusted else " (unverified)"
        d.add(
            String(
                n.x + 8,
                flip(n.y + 46),
                _trim(n.detail, 26) + tail,
                fontName="Helvetica",
                fontSize=7,
                fillColor=muted,
            )
        )
    if max_width and w > max_width:
        scale = max_width / w
        d.scale(scale, scale)
        d.width, d.height = w * scale, h * scale
    return d
