#!/usr/bin/env python3
"""Deterministic HAR analyzer for cookie-consent / CIPA audits.

Parses one HAR per consent state, classifies every third-party request and every
cookie set against vendors.json (authoritative, no model guessing), and emits a
findings.json plus a console summary. report.py turns findings.json into the
client-facing markdown deliverable.

Every number here traces back to a HAR entry: fully reproducible. Unknown domains
are reported as "unclassified - analyst review required", never guessed.

Usage:
    analyze.py --store examplestore.com \\
        --har none=captures/none.har \\
        --har decline=captures/decline.har \\
        --har accept=captures/accept.har \\
        --har gpc=captures/gpc.har \\
        [--out findings.json] [--registry vendors.json]

States are free-form labels; the report understands these canonical ones:
    none     first load, no banner interaction (the pre-consent baseline)
    decline  reject-all / decline
    accept   accept-all
    gpc      GPC signal present (Sec-GPC: 1)
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))


def load_registry(path):
    with open(path) as f:
        reg = json.load(f)
    # Pre-sort vendor domains most-specific (longest) first so
    # connect.facebook.net beats facebook.net and analytics.google.com beats google.com.
    flat = []
    for v in reg["vendors"]:
        for d in v["domains"]:
            flat.append((d, v["vendor"], v["category"]))
    flat.sort(key=lambda x: len(x[0]), reverse=True)
    reg["_domain_index"] = flat
    reg["_cookie_index"] = sorted(
        [(c["prefix"], c["vendor"], c["category"]) for c in reg["tracker_cookies"]],
        key=lambda x: len(x[0]),
        reverse=True,
    )
    reg["_first_party_infra"] = set(reg.get("first_party_infra", []))
    reg["_functional_cookies"] = set(reg.get("functional_cookies", []))
    return reg


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def matches(host, domain):
    return host == domain or host.endswith("." + domain)


def classify_host(host, reg):
    for domain, vendor, category in reg["_domain_index"]:
        if matches(host, domain):
            return vendor, category, domain
    return None, None, None


def classify_cookie(name, reg):
    for prefix, vendor, category in reg["_cookie_index"]:
        if name == prefix or name.startswith(prefix):
            return vendor, category
    return None, None


def is_first_party(host, store_domains, reg):
    if any(matches(host, d) for d in store_domains):
        return True
    return any(matches(host, d) for d in reg["_first_party_infra"])


def analyze_har(path, store_domains, reg):
    with open(path) as f:
        har = json.load(f)
    entries = har["log"]["entries"]

    # domain -> {vendor, category, requests}
    third_party = {}
    unclassified = defaultdict(int)
    gpc_signal_sent = False
    cookie_source_seen = False  # did this HAR carry ANY cookie data at all?
    # cookie identity -> {name, domain, vendor, category, first_party}
    cookies = {}

    for e in entries:
        req = e.get("request", {})
        url = req.get("url", "")
        host = host_of(url)
        if not host:
            continue

        # Confirm the GPC signal was actually transmitted (capture validity check).
        for h in req.get("headers", []):
            if h.get("name", "").lower() == "sec-gpc" and h.get("value", "").strip() == "1":
                gpc_signal_sent = True

        fp = is_first_party(host, store_domains, reg)
        if not fp:
            vendor, category, matched = classify_host(host, reg)
            if vendor:
                key = host
                if key not in third_party:
                    third_party[key] = {"host": host, "vendor": vendor, "category": category, "requests": 0}
                third_party[key]["requests"] += 1
            else:
                unclassified[host] += 1

        # Cookies set via Set-Cookie response headers.
        resp = e.get("response", {})
        for h in resp.get("headers", []):
            if h.get("name", "").lower() == "set-cookie":
                cookie_source_seen = True
                for line in h.get("value", "").split("\n"):
                    cname = line.split("=", 1)[0].strip()
                    if cname:
                        _record_cookie(cookies, cname, host, fp, reg)
        # Parsed response cookies (HAR sometimes only fills these).
        for c in resp.get("cookies", []) or []:
            cookie_source_seen = True
            cname = c.get("name", "")
            if cname:
                _record_cookie(cookies, cname, host, fp, reg)

    creator = har["log"].get("creator") or {}
    return {
        "har_file": os.path.basename(path),
        "har_creator": " ".join(str(creator.get(k, "")) for k in ("name", "version")).strip(),
        "entries": len(entries),
        "gpc_signal_sent": gpc_signal_sent,
        "cookie_data_present": cookie_source_seen,
        "third_party": sorted(third_party.values(), key=lambda x: (-x["requests"], x["host"])),
        "unclassified": sorted([{"host": h, "requests": n} for h, n in unclassified.items()], key=lambda x: -x["requests"]),
        "cookies": sorted(cookies.values(), key=lambda x: (x["category"] or "zzz", x["name"])),
    }


def _record_cookie(cookies, name, host, first_party, reg):
    vendor, category = classify_cookie(name, reg)
    if not vendor and name in reg["_functional_cookies"]:
        vendor, category = "Functional/Shopify", "functional"
    key = (name, host)
    if key not in cookies:
        cookies[key] = {
            "name": name,
            "domain": host,
            "vendor": vendor,
            "category": category or ("functional" if first_party else "unclassified"),
            "tracker": bool(vendor) and category not in (None, "functional", "cdn"),
        }


def cross_state(states, reg):
    """Build the findings that matter: what fires when it should not."""
    sensitive = set(reg.get("cipa_sensitive_categories", []))

    def vendors_in(state_key):
        st = states.get(state_key)
        return {tp["host"]: tp for tp in st["third_party"]} if st else {}

    def tracker_cookies_in(state_key):
        st = states.get(state_key)
        return [c for c in st["cookies"] if c["tracker"]] if st else []

    out = {}
    # Pre-consent firing: whatever loads in the no-interaction baseline.
    if "none" in states:
        v = vendors_in("none")
        out["pre_consent_vendors"] = sorted(
            [tp for tp in v.values() if tp["category"] in sensitive],
            key=lambda x: x["category"],
        )
        out["pre_consent_tracker_cookies"] = tracker_cookies_in("none")
    # Post-decline firing: sensitive vendors still present after reject-all.
    if "decline" in states:
        v = vendors_in("decline")
        out["post_decline_vendors"] = sorted(
            [tp for tp in v.values() if tp["category"] in sensitive],
            key=lambda x: x["category"],
        )
        out["post_decline_tracker_cookies"] = tracker_cookies_in("decline")
    # GPC handling: sensitive vendors that fire under GPC anyway. Compare against
    # accept to note what GPC did NOT suppress.
    if "gpc" in states:
        vg = vendors_in("gpc")
        out["gpc_signal_sent"] = states["gpc"].get("gpc_signal_sent", False)
        out["gpc_vendors_still_firing"] = sorted(
            [tp for tp in vg.values() if tp["category"] in sensitive],
            key=lambda x: x["category"],
        )
        out["gpc_tracker_cookies"] = tracker_cookies_in("gpc")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", required=True, help="Primary store domain, e.g. examplestore.com (also matches www.)")
    ap.add_argument("--har", action="append", default=[], metavar="STATE=PATH",
                    help="Repeatable. STATE is a label (none/decline/accept/gpc); PATH is the HAR file.")
    ap.add_argument("--registry", default=os.path.join(HERE, "vendors.json"))
    ap.add_argument("--out", default=None, help="Write findings JSON here (default: stdout summary only).")
    args = ap.parse_args()

    if not args.har:
        ap.error("at least one --har STATE=PATH is required")

    reg = load_registry(args.registry)
    store = args.store.lower().replace("www.", "")
    store_domains = [store]

    states = {}
    for spec in args.har:
        if "=" not in spec:
            ap.error(f"--har expects STATE=PATH, got: {spec}")
        state, path = spec.split("=", 1)
        if not os.path.exists(path):
            ap.error(f"HAR not found: {path}")
        states[state.strip()] = analyze_har(path, store_domains, reg)

    findings = {
        "store": store,
        "registry_version": reg.get("version"),
        "states": states,
        "cross_state": cross_state(states, reg),
    }

    if args.out:
        with open(args.out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"Wrote {args.out}")

    _print_summary(findings, reg)


def _print_summary(findings, reg):
    print(f"\n=== HAR analysis: {findings['store']} (registry {findings['registry_version']}) ===")
    for state, st in findings["states"].items():
        trackers = [c for c in st["cookies"] if c["tracker"]]
        gpc = " [Sec-GPC sent]" if st.get("gpc_signal_sent") else ""
        print(f"\n-- state '{state}' ({st['har_file']}, {st['entries']} entries){gpc} --")
        if not st.get("cookie_data_present"):
            print("   !! WARNING: this HAR carries NO cookie data (0 Set-Cookie headers). Cookie findings")
            print("      are BLIND, not clean. Recapture with capture.py (full HAR mode) before relying on them.")
        print(f"   third-party vendors: {len(st['third_party'])}   unclassified domains: {len(st['unclassified'])}   tracker cookies: {len(trackers)}")
        by_cat = defaultdict(list)
        for tp in st["third_party"]:
            by_cat[tp["category"]].append(tp["vendor"])
        for cat in sorted(by_cat):
            vs = sorted(set(by_cat[cat]))
            print(f"     {cat:18s} {', '.join(vs)}")
        if st["unclassified"]:
            print(f"     {'UNCLASSIFIED':18s} {', '.join(u['host'] for u in st['unclassified'][:12])}"
                  + (" ..." if len(st["unclassified"]) > 12 else ""))

    cs = findings["cross_state"]
    print("\n-- cross-state findings --")
    if "pre_consent_vendors" in cs:
        print(f"   CIPA-sensitive vendors firing pre-consent (state 'none'): {len(cs['pre_consent_vendors'])}")
        for tp in cs["pre_consent_vendors"]:
            print(f"     [{tp['category']}] {tp['vendor']} ({tp['host']})")
    if "post_decline_vendors" in cs:
        print(f"   CIPA-sensitive vendors still firing after DECLINE: {len(cs['post_decline_vendors'])}")
        for tp in cs["post_decline_vendors"]:
            print(f"     [{tp['category']}] {tp['vendor']} ({tp['host']})")
    if "gpc_vendors_still_firing" in cs:
        sent = "yes" if cs.get("gpc_signal_sent") else "NO (signal not detected in HAR!)"
        print(f"   GPC signal transmitted: {sent}")
        print(f"   CIPA-sensitive vendors firing under GPC: {len(cs['gpc_vendors_still_firing'])}")
        for tp in cs["gpc_vendors_still_firing"]:
            print(f"     [{tp['category']}] {tp['vendor']} ({tp['host']})")


if __name__ == "__main__":
    main()
