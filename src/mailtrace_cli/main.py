"""``mailtrace`` command-line interface.

Examples::

    mailtrace analyze suspicious.eml --offline
    mailtrace analyze suspicious.eml --json out.json --agency-domain example-pd.gov
    mailtrace new-case --base ./cases --number 26-001234 --examiner "Det. R. Example" --agency "Example PD"
    mailtrace intake ./cases/26-001234 suspicious.eml
    mailtrace audit-verify ./cases/26-001234
    type headers.txt | mailtrace paste --offline
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mailtrace_core.analysis.engine import analyze
from mailtrace_core.case.audit import verify_audit_log
from mailtrace_core.case.manager import Case
from mailtrace_core.case.settings import Settings, load_settings
from mailtrace_core.models import AnalysisResult, ParsedEmail, to_jsonable
from mailtrace_core.parsing import parse_file, parse_raw_headers
from mailtrace_core.util import netguard
from mailtrace_core.util.defang import defang_email, defang_ip


def _resolver(offline: bool) -> object | None:
    if offline:
        netguard.set_offline(True)
        return None
    from mailtrace_core.enrichment.dns_lookup import DnsResolver

    return DnsResolver()


def _settings(args: argparse.Namespace) -> Settings:
    s = load_settings()
    for d in getattr(args, "agency_domain", None) or []:
        s.agency_domains.append(d)
    for d in getattr(args, "recipient_domain", None) or []:
        s.trusted_recipient_domains.append(d)
    if getattr(args, "geoip_city", None):
        s.geoip_city_db = args.geoip_city
    if getattr(args, "geoip_asn", None):
        s.geoip_asn_db = args.geoip_asn
    return s


def _run_enrichment(
    result: AnalysisResult, settings: Settings, resolver: object | None, offline: bool, case: Case | None
) -> None:
    from mailtrace_core.enrichment.http import HttpClient
    from mailtrace_core.enrichment.runner import run_enrichment

    http = None if offline else HttpClient()
    cache_path = case.working_dir / "enrichment_cache.json" if case else None
    try:
        run_enrichment(result, settings, cache_path=cache_path, resolver=resolver, http=http)  # type: ignore[arg-type]
    finally:
        if http is not None:
            http.close()


def _print_summary(result: AnalysisResult) -> None:
    pe: ParsedEmail = result.email
    w = sys.stdout.write
    w(f"Source        : {pe.source_name} ({pe.source_format.value})\n")
    w(f"Subject       : {pe.subject}\n")
    if pe.from_:
        w(f"From          : {pe.from_.display_name!r} {defang_email(pe.from_.address)}\n")
    if pe.reply_to:
        w(f"Reply-To      : {', '.join(defang_email(a.address) for a in pe.reply_to)}\n")
    if pe.return_path:
        w(f"Return-Path   : {defang_email(pe.return_path.address) or '<>'}\n")
    w(f"Date          : {pe.date.isoformat() if pe.date else pe.header('Date')}\n")
    w(f"Message-ID    : {pe.message_id}\n\n")

    w(f"Received chain ({len(pe.hops)} hops, origin first):\n")
    for h in pe.hops:
        flag = "TRUSTED " if h.trusted else "unverif."
        ts = h.timestamp.isoformat() if h.timestamp else "(no time)"
        delay = f"+{h.delay_seconds:.0f}s" if h.delay_seconds is not None else ""
        ip = defang_ip(h.from_ip) if h.from_ip else "?"
        w(
            f"  [{h.index}] {flag} {ts:32} {delay:>9}  from {h.from_host or '?'} [{ip}] "
            f"by {h.by_host or '?'} with {h.protocol or '?'}\n"
        )
        for a in h.anomalies:
            w(f"        ! {a}\n")
    w("\nOrigin candidates:\n")
    for c in pe.origin_candidates:
        private = " (private)" if c.is_private else ""
        w(f"  {defang_ip(c.ip):24} {c.confidence.value:10} {c.source}{private}\n")

    a = pe.auth
    w("\nAuthentication:\n")
    for r in a.reported:
        w(f"  reported {r.method}={r.result} by {r.authserv_id}\n")
    if a.spf:
        w(f"  SPF   : {a.spf.result:10} {a.spf.detail}\n")
    if a.dkim:
        w(f"  DKIM  : {a.dkim.result:10} d={a.dkim.domain} s={a.dkim.selector} {a.dkim.detail}\n")
    if a.dmarc:
        w(f"  DMARC : {a.dmarc.result:10} p={a.dmarc.policy} {a.dmarc.detail}\n")
    if result.skipped_checks:
        w(f"  skipped: {', '.join(result.skipped_checks)}\n")

    w(f"\nURLs ({len(pe.urls)}):\n")
    for u in pe.urls:
        extra = " MISMATCH" if u.display_mismatch else ""
        w(f"  {u.source:16} {u.defanged}{extra}\n")
    w(f"\nAttachments ({len(pe.attachments)}):\n")
    for att in pe.attachments:
        w(f"  {att.filename}  {att.size} bytes  sha256={att.sha256}\n")
        mismatch = "TYPE MISMATCH" if att.type_mismatch else ""
        w(f"      declared={att.declared_type} detected={att.detected_type} {mismatch}\n")
        for n in att.notes:
            w(f"      - {n}\n")

    w(f"\nFindings ({len(result.findings)}):\n")
    for f in result.findings:
        w(f"  [{f.severity.value.upper():6}] [{f.confidence.value:10}] {f.rule_id} {f.title}\n")
        for e in f.evidence[:3]:
            w(f"      {e.source}: {e.value[:120]}\n")
    if pe.warnings:
        w("\nWarnings:\n")
        for wmsg in pe.warnings:
            w(f"  - {wmsg}\n")


def _print_enrichment(result: AnalysisResult) -> None:
    rep = result.enrichment
    if rep is None:
        return
    w = sys.stdout.write
    w(f"\nEnrichment ({rep.lookups_performed} lookups, {rep.lookups_cached} from case cache):\n")
    w("  IP addresses:\n")
    for ip in rep.ips:
        flags = [
            n
            for n, v in (("hosting", ip.hosting), ("vpn", ip.vpn), ("proxy", ip.proxy), ("tor", ip.tor))
            if v
        ]
        asn = f"AS{ip.asn} {ip.asn_org}" if ip.asn else (ip.asn_org or "")
        loc = "/".join(x for x in (ip.country, ip.region, ip.city) if x)
        w(f"    {defang_ip(ip.ip):22} {asn}  {loc}  [{'; '.join(ip.roles)}]\n")
        if ip.reverse_dns:
            w(f"        rDNS: {', '.join(ip.reverse_dns)}\n")
        if ip.network_name or ip.network_cidr:
            w(
                f"        network: {ip.network_name or ''} {ip.network_cidr or ''} "
                f"({ip.rdap_registry or 'RDAP'})  abuse: {', '.join(ip.abuse_contacts) or '-'}\n"
            )
        if flags:
            w(f"        flags: {', '.join(flags)}  ({'; '.join(ip.flag_reasons)})\n")
        for v in ip.reputation:
            w(f"        {v.provider}: {v.verdict} ({v.summary})\n")
    w("  Domains:\n")
    for d in rep.domains:
        if d.created:
            age = f"created {d.created} ({d.age_days} d{' NEW' if d.is_new else ''})"
        else:
            age = "no registration data"
        w(f"    {d.domain:40} [{'; '.join(d.roles)}]\n")
        w(f"        registrar: {d.registrar or '-'}  {age}  via {d.whois_source or '-'}\n")
        if d.registrar_abuse_email or d.registrar_abuse_phone:
            w(f"        registrar abuse: {d.registrar_abuse_email or ''} {d.registrar_abuse_phone or ''}\n")
        if d.a or d.mx or d.ns:
            w(
                f"        A: {', '.join(d.a) or '-'}  MX: {', '.join(d.mx) or '-'}  "
                f"NS: {', '.join(d.ns) or '-'}\n"
            )
        for v in d.reputation:
            w(f"        {v.provider}: {v.verdict} ({v.summary})\n")
    if rep.url_reputation:
        w("  URL reputation:\n")
        for v in rep.url_reputation:
            w(f"    {v.provider:12} {v.verdict:10} {v.summary:24} {v.target[:80]}\n")
    if rep.attachment_reputation:
        w("  Attachment reputation (hash lookups only):\n")
        for v in rep.attachment_reputation:
            w(f"    {v.provider:12} {v.verdict:10} {v.summary}  {v.detail[:80]}\n")
    w("  Legal process targets:\n")
    for t in rep.legal_targets:
        contact = t.portal or t.email or t.guidelines_url
        verify = "  (verify before use)" if t.verify_before_use else ""
        w(f"    {t.provider_name} - {t.role}\n        matched: {t.matched_on}\n")
        w(f"        contact: {contact}{verify}\n")
        for r in t.records_available[:4]:
            w(f"          - {r}\n")
    if rep.preservation_note:
        w(f"  Preservation: {rep.preservation_note}\n")
    if rep.risk:
        w(f"\nRisk score: {rep.risk.score}/100 ({rep.risk.band})\n")
        for f in rep.risk.factors:
            w(f"    {f.points:+4d}  {f.name}  [{f.source}] {f.evidence}\n")
        for n in rep.risk.notes:
            w(f"    note: {n}\n")
    if rep.skipped:
        w("  Skipped providers:\n")
        for sk in rep.skipped:
            w(f"    - {sk}\n")


def cmd_analyze(args: argparse.Namespace) -> int:
    settings = _settings(args)
    resolver = _resolver(args.offline)
    case: Case | None = Case.open(Path(args.case)) if args.case else None
    path = Path(args.path)
    if case:
        item = case.intake(path)
        path = Path(item.stored_path)
        case.log("analyze_start", item_id=item.item_id, offline=args.offline)
    pe = parse_file(path, settings, resolver)  # type: ignore[arg-type]
    result = analyze(pe, settings)
    if args.enrich:
        _run_enrichment(result, settings, resolver, args.offline, case)
    if case:
        case.log(
            "analyze_done",
            findings=len(result.findings),
            skipped=result.skipped_checks,
            warnings=len(pe.warnings),
            enriched=bool(args.enrich),
            risk=result.enrichment.risk.score if result.enrichment and result.enrichment.risk else None,
            lookups=result.enrichment.lookups_performed if result.enrichment else 0,
        )
    if args.json:
        Path(args.json).write_text(json.dumps(to_jsonable(result), indent=2), encoding="utf-8")
        sys.stdout.write(f"wrote {args.json}\n")
    else:
        _print_summary(result)
        _print_enrichment(result)
    return 0


def cmd_paste(args: argparse.Namespace) -> int:
    settings = _settings(args)
    resolver = _resolver(args.offline)
    text = sys.stdin.read()
    pe = parse_raw_headers(text, "stdin", settings, resolver)  # type: ignore[arg-type]
    result = analyze(pe, settings)
    if args.enrich:
        _run_enrichment(result, settings, resolver, args.offline, None)
    if args.json:
        Path(args.json).write_text(json.dumps(to_jsonable(result), indent=2), encoding="utf-8")
    else:
        _print_summary(result)
        _print_enrichment(result)
    return 0


def cmd_new_case(args: argparse.Namespace) -> int:
    case = Case.create(Path(args.base), args.number, args.examiner, args.agency)
    sys.stdout.write(f"created {case.root}\n")
    return 0


def cmd_intake(args: argparse.Namespace) -> int:
    case = Case.open(Path(args.case))
    for p in args.paths:
        item = case.intake(Path(p))
        sys.stdout.write(f"{item.item_id}  sha256={item.sha256}  md5={item.md5}  {item.filename}\n")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    ok, problems = verify_audit_log(Path(args.case) / "audit.jsonl")
    if ok:
        sys.stdout.write("audit log chain intact\n")
        return 0
    for p in problems:
        sys.stdout.write(f"PROBLEM: {p}\n")
    return 2


def _intake_if_case(args: argparse.Namespace) -> tuple[Case | None, Path, object | None]:
    case: Case | None = Case.open(Path(args.case)) if args.case else None
    path = Path(args.path)
    item = None
    if case:
        item = case.intake(path)
        path = Path(item.stored_path)
    return case, path, item


def cmd_report(args: argparse.Namespace) -> int:
    from mailtrace_core.reporting import FORMATS, build_report, default_filename, write_report

    settings = _settings(args)
    resolver = _resolver(args.offline)
    case, path, item = _intake_if_case(args)
    if case:
        case.log(
            "analyze_start",
            item_id=item.item_id,
            offline=args.offline,
            enrich=bool(args.enrich),
            purpose="report",
        )
    pe = parse_file(path, settings, resolver)  # type: ignore[arg-type]
    result = analyze(pe, settings)
    if args.enrich:
        _run_enrichment(result, settings, resolver, args.offline, case)
    report = build_report(result, settings, case, item)  # type: ignore[arg-type]
    formats = list(FORMATS) if args.format == "all" else [args.format]
    out_dir = Path(args.out) if args.out else (case.report_dir if case else Path.cwd())
    for fmt in formats:
        target = out_dir / default_filename(report, fmt)
        if args.out and len(formats) == 1 and Path(args.out).suffix.lower() == f".{fmt}":
            target = Path(args.out)
        written, sha = write_report(report, fmt, target, case)
        print(f"{fmt.upper():5} {written}  sha256={sha}")
    print(f"report id {report.meta.report_id}: {report.verdict.label} ({report.verdict.confidence.value})")
    return 0


def cmd_draft(args: argparse.Namespace) -> int:
    from mailtrace_core.reporting import build_report
    from mailtrace_core.reporting.drafts import all_drafts, draft_as_text, write_eml_draft

    settings = _settings(args)
    resolver = _resolver(args.offline)
    case, path, item = _intake_if_case(args)
    pe = parse_file(path, settings, resolver)  # type: ignore[arg-type]
    result = analyze(pe, settings)
    if args.enrich:
        _run_enrichment(result, settings, resolver, args.offline, case)
    report = build_report(result, settings, case, item)  # type: ignore[arg-type]
    eml = str(path) if path.suffix.lower() == ".eml" else None
    drafts = [
        d for d in all_drafts(report, settings, eml) if args.kind == "all" or d.kind.startswith(args.kind)
    ]
    out_dir = (
        Path(args.out) if args.out else ((case.report_dir / "drafts") if case else Path.cwd() / "drafts")
    )
    for n, d in enumerate(drafts, 1):
        if d.to:
            target = out_dir / f"{d.kind}-{n}-{report.meta.report_id}.eml"
            write_eml_draft(d, target, settings.reporter_email)
            if case:
                case.log(
                    "draft_saved_eml",
                    kind=d.kind,
                    to=d.to,
                    path=str(target),
                    attachments=[Path(a).name for a in d.attachments],
                )
            print(f"== {d.title}")
            print(f"   saved unsent draft: {target}")
            print(f"   {d.notes}")
        else:
            print(f"== {d.title}")
            print(f"   {d.notes}")
            print()
            print(draft_as_text(d))
            print()
            if case:
                case.log("draft_printed", kind=d.kind)
    return 0


def cmd_check_updates(args: argparse.Namespace) -> int:
    from mailtrace_core import __version__
    from mailtrace_core.updates import check_for_updates

    settings = load_settings()
    res = check_for_updates(enabled=settings.update_check_enabled or args.force, force=args.force)
    print(f"current version {__version__}")
    print(f"status: {res.status}" + (f" ({res.detail})" if res.detail else ""))
    if res.status == "update_available":
        print(f"latest: {res.latest_version} ({res.tag}) published {res.published_at}")
        print(f"release page: {res.release_url}")
        for a in res.assets:
            print(f"  asset {a.name} ({a.size} bytes)" + (f" sha256={a.sha256}" if a.sha256 else ""))
        if res.release_notes:
            print()
            print(res.release_notes)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailtrace", description="Passive forensic email analysis")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--offline", action="store_true", help="disable all DNS lookups")
        sp.add_argument("--json", help="write full result as JSON to this path")
        sp.add_argument("--agency-domain", action="append", help="your agency's domain (repeatable)")
        sp.add_argument(
            "--recipient-domain", action="append", help="recipient mail domain for hop trust (repeatable)"
        )
        sp.add_argument(
            "--enrich",
            action="store_true",
            help="run enrichment (GeoIP, RDAP/WHOIS, reputation, legal-process mapping, risk score); "
            "with --offline only the local GeoLite2 database is consulted",
        )
        sp.add_argument("--geoip-city", help="path to GeoLite2-City.mmdb (overrides settings)")
        sp.add_argument("--geoip-asn", help="path to GeoLite2-ASN.mmdb (overrides settings)")

    a = sub.add_parser("analyze", help="parse and analyse a .eml/.msg/.txt file")
    a.add_argument("path")
    a.add_argument("--case", help="case folder; the file is ingested into it first")
    common(a)
    a.set_defaults(func=cmd_analyze)

    ps = sub.add_parser("paste", help="read raw headers (or a full message) from stdin")
    common(ps)
    ps.set_defaults(func=cmd_paste)

    n = sub.add_parser("new-case")
    n.add_argument("--base", required=True)
    n.add_argument("--number", required=True)
    n.add_argument("--examiner", required=True)
    n.add_argument("--agency", required=True)
    n.set_defaults(func=cmd_new_case)

    i = sub.add_parser("intake", help="ingest files into an existing case")
    i.add_argument("case")
    i.add_argument("paths", nargs="+")
    i.set_defaults(func=cmd_intake)

    v = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    v.add_argument("case")
    v.set_defaults(func=cmd_audit_verify)

    rp = sub.add_parser("report", help="analyse and write a PDF/HTML/JSON report")
    rp.add_argument("path")
    rp.add_argument("--case", help="case folder; the file is ingested into it first")
    rp.add_argument("--format", choices=["pdf", "html", "json", "all"], default="all")
    rp.add_argument("--out", help="output directory (or a file path when a single format is chosen)")
    common(rp)
    rp.set_defaults(func=cmd_report)

    dr = sub.add_parser("draft", help="produce report drafts (IC3, FTC, APWG, abuse desks); never sends")
    dr.add_argument("path")
    dr.add_argument("--case", help="case folder; the file is ingested into it first")
    dr.add_argument("--kind", choices=["all", "ic3", "ftc", "apwg", "abuse"], default="all")
    dr.add_argument("--out", help="directory for .eml drafts (default: <case>/report/drafts)")
    common(dr)
    dr.set_defaults(func=cmd_draft)

    cu = sub.add_parser("check-updates", help="query GitHub Releases for a newer MailTrace (never installs)")
    cu.add_argument(
        "--force", action="store_true", help="ignore the 24-hour throttle and the disabled setting"
    )
    cu.set_defaults(func=cmd_check_updates)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # RTL-override etc. must not crash the console
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
