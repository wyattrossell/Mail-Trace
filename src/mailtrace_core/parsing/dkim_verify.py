"""Independent DKIM re-verification with dkimpy.

The reported ``dkim=pass`` in Authentication-Results is only an assertion by
the receiving server. Here we recompute the signature over the actual bytes
we were given and fetch the public key ourselves through the resolver.
"""

from __future__ import annotations

import logging
import re

from mailtrace_core.enrichment.dns_lookup import DnsTempError, Resolver, dkim_dnsfunc
from mailtrace_core.models import DkimVerification

_TAG_RE = re.compile(r"([a-z]+)\s*=\s*([^;]*)", re.IGNORECASE)


def parse_signature_tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for m in _TAG_RE.finditer(" ".join(value.split())):
        tags[m.group(1).lower()] = m.group(2).replace(" ", "").strip()
    return tags


def _signature_headers(headers: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [parse_signature_tags(v) for k, v in headers if k.lower() == "dkim-signature"]


def verify_dkim(
    raw_bytes: bytes,
    headers: list[tuple[str, str]],
    resolver: Resolver | None,
    from_domain: str | None = None,
) -> DkimVerification:
    """Verify every DKIM-Signature present; report the most relevant one.

    Preference order: a passing signature aligned with the From domain, then
    any passing signature, then the first signature's failure reason.
    """
    sigs = _signature_headers(headers)
    if not sigs:
        return DkimVerification(None, None, "none", detail="no DKIM-Signature header")
    if not raw_bytes:
        s = sigs[0]
        return DkimVerification(
            s.get("d"),
            s.get("s"),
            "skipped",
            detail="original message bytes unavailable (e.g. .msg source)",
            signed_headers=s.get("h", "").split(":") if s.get("h") else [],
        )
    if resolver is None:
        s = sigs[0]
        return DkimVerification(
            s.get("d"),
            s.get("s"),
            "skipped",
            detail="DNS disabled or offline",
            signed_headers=s.get("h", "").split(":") if s.get("h") else [],
        )

    import dkim

    logger = logging.getLogger("mailtrace.dkim")
    dnsfunc = dkim_dnsfunc(resolver)
    results: list[DkimVerification] = []
    for idx, s in enumerate(sigs):
        signed = s.get("h", "").split(":") if s.get("h") else []
        d, sel = s.get("d"), s.get("s")
        try:
            verifier = dkim.DKIM(raw_bytes, logger=logger)
            ok = verifier.verify(idx=idx, dnsfunc=dnsfunc)
            if ok:
                results.append(DkimVerification(d, sel, "pass", "signature verified", signed))
            else:
                results.append(
                    DkimVerification(
                        d,
                        sel,
                        "fail",
                        "signature did not verify (message altered, wrong key, or forged)",
                        signed,
                    )
                )
        except DnsTempError as exc:
            results.append(DkimVerification(d, sel, "temperror", f"DNS failure: {exc}", signed))
        except dkim.KeyFormatError as exc:
            results.append(DkimVerification(d, sel, "permerror", f"public key problem: {exc}", signed))
        except dkim.DKIMException as exc:
            results.append(DkimVerification(d, sel, "fail", f"{type(exc).__name__}: {exc}", signed))
        except Exception as exc:  # noqa: BLE001 - never let a library bug abort analysis
            results.append(DkimVerification(d, sel, "permerror", f"verifier error: {exc}", signed))

    fd = (from_domain or "").lower()
    for r in results:
        if (
            r.result == "pass"
            and r.domain
            and (r.domain.lower() == fd or fd.endswith("." + r.domain.lower()))
        ):
            r.detail += f" ({len(results)} signature(s) present)"
            return r
    for r in results:
        if r.result == "pass":
            r.detail += f"; not aligned with From domain ({len(results)} signature(s) present)"
            return r
    first = results[0]
    if len(results) > 1:
        first.detail += f"; {len(results)} signatures present, none verified"
    return first
