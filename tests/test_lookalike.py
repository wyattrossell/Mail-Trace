from __future__ import annotations

from mailtrace_core.parsing.lookalike import compare_domain, damerau_levenshtein, skeleton

WATCH = ["paypal.com", "microsoft.com", "examplecounty-sheriff.gov.test", "irs.gov"]


def test_skeleton_folds_confusables() -> None:
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("pаypal") == "paypal"  # Cyrillic a
    assert skeleton("PayPa1") == "paypal"
    assert skeleton("micr0soft") == "microsoft"


def test_distance() -> None:
    assert damerau_levenshtein("sheriff", "sherriff") == 1
    assert damerau_levenshtein("paypal", "papyal") == 1  # transposition
    assert damerau_levenshtein("abc", "abc") == 0


def test_legitimate_domains_are_not_lookalikes() -> None:
    assert compare_domain("paypal.com", WATCH) is None
    assert compare_domain("mail.paypal.com", WATCH) is None
    assert compare_domain("mx1.examplecounty-sheriff.gov.test", WATCH) is None
    assert compare_domain("unrelated-company.test", WATCH) is None


def test_homoglyph_and_idn() -> None:
    m = compare_domain("login.rnicrosoft.example", WATCH)
    assert m and m.kind == "homoglyph" and m.brand == "microsoft.com"
    m = compare_domain("xn--pypal-4ve.example", WATCH)
    assert m and m.kind == "idn" and m.brand == "paypal.com"


def test_typo_affix_subdomain_tld() -> None:
    m = compare_domain("examplecounty-sherriff.gov.test", WATCH)
    assert m and m.kind == "typo" and m.brand == "examplecounty-sheriff.gov.test"
    m = compare_domain("paypal-notices.example", WATCH)
    assert m and m.kind == "affix"
    m = compare_domain("paypal.com.secure-login.example", WATCH)
    assert m and m.kind == "brand-subdomain"
    m = compare_domain("paypal.evil.example", WATCH)
    assert m and m.kind == "brand-subdomain"
    m = compare_domain("paypal.net", WATCH)
    assert m and m.kind == "tld-swap"


def test_short_brand_labels_do_not_typo_match() -> None:
    # 'irs' is too short for edit-distance matching; 'its.gov' must not fire.
    assert compare_domain("its.gov", WATCH) is None
