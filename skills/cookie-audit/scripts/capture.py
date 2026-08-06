#!/usr/bin/env python3
"""Forensic consent-state capture for Shopify cookie/CIPA audits.

Records one full HAR per consent state from a clean, isolated browser context so a
CIPA finding rests on a real pre-consent baseline. Deliberately NOT driven through
an everyday browser: a daily-driver profile carries cookies/extensions/logins that
contaminate the "no interaction, first load" state. Playwright gives a fresh
context per state, controllable GPC, and a stable IP (run it from a residential
connection; datacenter IPs trip bot defenses and can change what fires).

States captured (each = its own fresh context, cleared storage):
    none     first load, banner untouched  -> the pre-consent baseline
    decline  reject-all clicked
    accept   accept-all clicked
    gpc      Sec-GPC:1 header + navigator.globalPrivacyControl=true, banner untouched

Per state it runs the standard funnel: home -> collection -> PDP -> add-to-cart ->
cart (use --checkout to also enter checkout). Writes {state}.har + {state}-{step}.png
+ {state}-console.log into the output dir. Feed the HARs to analyze.py.

Usage:
    capture.py --config config.yaml [--out captures/] [--checkout] [--headed] [--state none,decline,accept,gpc]

Requires: pip install playwright pyyaml && playwright install chromium
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FUNNEL_STEPS = ["home", "collection", "pdp", "cart"]
DEFAULT_STATES = ["none", "decline", "accept", "gpc"]


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML not installed. Run: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


def load_cmp_profiles():
    with open(os.path.join(HERE, "cmp_profiles.json")) as f:
        return json.load(f)["profiles"]


def detect_and_get_selectors(page, cfg, profiles):
    """Return (accept_selector, decline_selector, cmp_name) or (None, None, None)."""
    # Inline override in config wins.
    inline = cfg.get("cmp") or {}
    if inline.get("accept") and inline.get("decline"):
        return inline["accept"], inline["decline"], inline.get("name", "config-inline")
    for prof in profiles:
        try:
            if page.query_selector(prof["detect"]):
                return prof["accept"], prof["decline"], prof["cmp"]
        except Exception:
            continue
    return None, None, None


def click_first(page, selector, timeout=4000):
    for sel in selector.split(","):
        sel = sel.strip()
        try:
            el = page.wait_for_selector(sel, timeout=timeout, state="visible")
            if el:
                el.click()
                return True
        except Exception:
            continue
    return False


def run_funnel(page, cfg, out, state, log, checkout):
    urls = {
        "home": cfg["home_url"],
        "collection": cfg["collection_url"],
        "pdp": cfg["pdp_url"],
    }
    for step in ["home", "collection", "pdp"]:
        page.goto(urls[step], wait_until="networkidle", timeout=45000)
        page.wait_for_timeout(1500)
        page.screenshot(path=os.path.join(out, f"{state}-{step}.png"))
        log.append(f"[{state}] loaded {step}: {urls[step]}")
    # Add to cart: prefer explicit selector, else Shopify /cart/add.js on the PDP variant.
    atc = cfg.get("add_to_cart_selector")
    if atc and click_first(page, atc):
        log.append(f"[{state}] clicked add-to-cart")
    else:
        vid = cfg.get("variant_id")
        if vid:
            page.evaluate(
                "async (id) => { await fetch('/cart/add.js', {method:'POST',"
                "headers:{'Content-Type':'application/json'},"
                "body: JSON.stringify({items:[{id:id,quantity:1}]})}); }", vid)
            log.append(f"[{state}] add-to-cart via /cart/add.js variant {vid}")
        else:
            log.append(f"[{state}] WARN: no add_to_cart_selector and no variant_id; skipped add-to-cart")
    page.wait_for_timeout(1500)
    page.goto(cfg.get("cart_url", cfg["home_url"].rstrip("/") + "/cart"),
              wait_until="networkidle", timeout=45000)
    page.screenshot(path=os.path.join(out, f"{state}-cart.png"))
    log.append(f"[{state}] loaded cart")
    if checkout:
        try:
            page.goto(cfg["home_url"].rstrip("/") + "/checkout", wait_until="networkidle", timeout=45000)
            page.screenshot(path=os.path.join(out, f"{state}-checkout.png"))
            log.append(f"[{state}] entered checkout")
        except Exception as e:
            log.append(f"[{state}] checkout entry failed: {e}")


def capture_state(browser, cfg, profiles, out, state, checkout):
    log = []
    har_path = os.path.join(out, f"{state}.har")
    context_kwargs = {
        "record_har_path": har_path,
        "record_har_mode": "full",
        "ignore_https_errors": False,
        "viewport": {"width": 1366, "height": 900},
    }
    if state == "gpc":
        context_kwargs["extra_http_headers"] = {"Sec-GPC": "1"}
    ctx = browser.new_context(**context_kwargs)
    if state == "gpc":
        ctx.add_init_script("Object.defineProperty(navigator,'globalPrivacyControl',{get:()=>true});")
    page = ctx.new_page()
    console_lines = []
    page.on("console", lambda m: console_lines.append(f"{m.type}: {m.text}"))

    # First load to reach the banner.
    page.goto(cfg["home_url"], wait_until="networkidle", timeout=45000)
    page.wait_for_timeout(2000)

    def _abort(msg):
        # Discard the partial HAR (just the pre-abort homepage) so it can never be
        # mistaken for a real captured state downstream.
        ctx.close()
        if os.path.exists(har_path):
            os.remove(har_path)
        sys.exit(msg)

    if state in ("decline", "accept"):
        accept_sel, decline_sel, cmp_name = detect_and_get_selectors(page, cfg, profiles)
        if not accept_sel:
            _abort(f"[{state}] No CMP banner detected and no inline cmp selectors in config. "
                   f"Add a profile to cmp_profiles.json or a 'cmp:' block to config.yaml. Aborting "
                   f"rather than mis-capturing (no partial HAR written).")
        target = accept_sel if state == "accept" else decline_sel
        clicked = click_first(page, target)
        log.append(f"[{state}] CMP={cmp_name} {'clicked' if clicked else 'FAILED to click'} {target}")
        if not clicked:
            _abort(f"[{state}] Found CMP '{cmp_name}' but could not click its {state} button ({target}). "
                   f"Selectors may have drifted; update cmp_profiles.json. Aborting (no partial HAR written).")
        page.wait_for_timeout(2000)

    run_funnel(page, cfg, out, state, log, checkout)

    with open(os.path.join(out, f"{state}-console.log"), "w") as f:
        f.write("\n".join(console_lines))
    ctx.close()  # flushes the HAR
    print("\n".join(log))
    return log


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="Per-store config.yaml (see config.example.yaml)")
    ap.add_argument("--out", default="captures", help="Output dir for HARs + artifacts")
    ap.add_argument("--state", default=",".join(DEFAULT_STATES),
                    help="Comma list of states to capture (default: none,decline,accept,gpc)")
    ap.add_argument("--checkout", action="store_true", help="Also enter /checkout per state (flakier)")
    ap.add_argument("--headed", action="store_true", help="Show the browser (default headless)")
    args = ap.parse_args()

    cfg = load_yaml(args.config)
    for req in ("home_url", "collection_url", "pdp_url"):
        if req not in cfg:
            sys.exit(f"config missing required key: {req}")
    profiles = load_cmp_profiles()
    os.makedirs(args.out, exist_ok=True)
    states = [s.strip() for s in args.state.split(",") if s.strip()]

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed)
        try:
            for state in states:
                print(f"\n=== capturing state: {state} ===")
                capture_state(browser, cfg, profiles, args.out, state, args.checkout)
        finally:
            browser.close()

    print(f"\nDone. HARs in {args.out}/. Next:")
    hars = " ".join(f"--har {s}={args.out}/{s}.har" for s in states)
    print(f"  analyze.py --store {cfg.get('store_domain','<domain>')} {hars} --out {args.out}/findings.json")


if __name__ == "__main__":
    main()
