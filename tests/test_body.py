from __future__ import annotations

from email.message import EmailMessage

from mailtrace_core.parsing.body import extract_bodies, extract_from_bodies, summarize_html

HTML = """<html><head><style>.x{background:url(https://css.test/bg.png)}</style>
<script src="https://js.test/a.js">alert(1)</script></head><body>
<p>Hello <a href="https://real.test/login">https://www.bank.test/secure</a></p>
<a href="mailto:x@y.test">mail</a>
<img src="https://track.test/p.gif" width="1" height="1">
<img src="cid:logo">
<form action="https://collect.test/post"><input name="u"></form>
<div style="display:none">hidden</div>
<meta http-equiv="refresh" content="0; url=https://redir.test/">
<p>Plain url in text: https://intext.test/x</p>
</body></html>"""


def test_summarize_html_collects_everything() -> None:
    s = summarize_html(HTML)
    assert ("https://real.test/login", "https://www.bank.test/secure") in s.links
    assert ("mailto:x@y.test", "mail") in s.links
    assert ("https://track.test/p.gif", "img") in s.sources
    assert ("https://js.test/a.js", "script") in s.sources
    assert ("https://redir.test/", "meta-refresh") in s.sources
    assert s.form_actions == ["https://collect.test/post"]
    assert s.pixels and s.pixels[0].src == "https://track.test/p.gif"
    assert s.has_script and s.has_forms and s.hidden_text_chunks == 1
    assert "alert(1)" not in s.text and "Hello" in s.text


def test_extract_from_bodies_inventory() -> None:
    ext = extract_from_bodies("See https://intext.test/x now", HTML, shorteners=[])
    by_norm = {(u.normalized, u.source): u for u in ext.urls}
    assert ("https://intext.test/x", "text") in by_norm
    assert ("https://intext.test/x", "html-text") in by_norm
    assert ("https://real.test/login", "html-href") in by_norm
    assert by_norm[("https://real.test/login", "html-href")].display_mismatch
    assert ("https://collect.test/post", "html-action") in by_norm
    assert ("https://track.test/p.gif", "html-src:img") in by_norm
    assert not any(u.raw.startswith("cid:") for u in ext.urls)
    assert any("<form>" in w for w in ext.warnings)
    assert any("hidden element" in w for w in ext.warnings)
    assert any("<script>" in w for w in ext.warnings)
    assert len(ext.pixels) == 1


def test_extract_bodies_from_multipart() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.test"
    msg.set_content("plain part")
    msg.add_alternative("<p>html part</p>", subtype="html")
    msg.add_attachment(b"data", maintype="text", subtype="plain", filename="notes.txt")
    text, html = extract_bodies(msg)
    assert text.strip() == "plain part"
    assert "html part" in html
    assert "data" not in text  # attachment text/plain is not body


def test_malformed_html_does_not_raise() -> None:
    s = summarize_html("<a href='x'><b>unclosed <div><p")
    assert s.links and s.links[0][0] == "x" and s.links[0][1].startswith("unclosed")
