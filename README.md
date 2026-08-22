# ecom-cookie-audit

**Point it at a store. It answers, with reproducible evidence: what fires
before consent, what still fires after decline, and what ignores GPC.**

Those are the three questions behind the wave of CIPA (California Invasion of
Privacy Act) wiretap and pen-register demand letters hitting online stores,
and the three questions a screenshot of a cookie banner cannot answer. This is
the audit pipeline that can, packaged as an agent skill (Claude Code plugin,
or any runtime that reads `SKILL.md`).

**capture → analyze → report**

1. **Capture** (`capture.py`): Playwright loads the store in four consent
   states — `none` (banner untouched), `decline`, `accept`, `gpc` (Sec-GPC
   header + `navigator.globalPrivacyControl`) — each in a fresh isolated
   browser context (no cookies, no extensions, no login), walks the funnel
   (home → collection → PDP → add-to-cart → cart), and records one full HAR
   per state plus screenshots and console logs. Consent banners are auto-driven
   via selector profiles for common Shopify CMPs (Shopify native, Pandectes,
   Consentmo, iubenda, OneTrust, CookieYes, Klaviyo, iSense); unknown CMPs
   abort loudly instead of mis-capturing.
2. **Analyze** (`analyze.py`): classifies every third-party request and every
   cookie against a versioned vendor registry (`vendors.json`, 129 vendors /
   33 tracker-cookie prefixes). Deterministic, no model guessing: unknown
   domains are flagged "unclassified — analyst review required", never
   inferred. Emits `findings.json`; every count traces to a HAR entry.
3. **Report** (`report.py`): a counsel-facing markdown diagnostic — per-state
   vendor inventory, pre-consent firing, post-decline firing, GPC handling,
   tracker cookies — with the legal-theory context each CIPA-sensitive
   category typically attracts (session replay, chat, ads pixels, email/SMS
   identity vendors, fingerprinting). Or `--triage` for a terse console read.

## The lane this stays in

**Diagnosis, not adjudication.** The report states observable network facts and
maps them to *potential exposure areas for counsel review*. It never asserts a
legal violation, never declares a store "compliant" or "non-compliant", and
never remediates on its own. That disclaimer is baked into every report the
tooling produces. If you need a compliance determination, that is your
attorney's call; hand them the report.

## Why forensic capture matters

Two traps this pipeline exists to avoid:

- **Chrome DevTools HAR exports strip Set-Cookie headers.** Since Chrome 130,
  DevTools sanitizes `Cookie`/`Set-Cookie`/`Authorization` out of exported HARs
  by default (there is a buried "Export HAR (with sensitive data)" option
  almost nobody uses). A naive analyzer reads an exported HAR, finds zero
  tracker cookies, and reports a clean store — when it was actually blind, and
  nothing in the file tells you whether it was sanitized or genuinely
  cookie-free. `analyze.py` detects cookie-less HARs and labels cookie findings
  "BLIND, not clean". Trustworthy cookie evidence comes from the Playwright
  capture (`record_har_mode=full`).
- **Your daily browser is a contaminated instrument.** Existing cookies,
  logins, and extensions change what fires on "first" load. Every capture state
  here gets a factory-fresh context, so the pre-consent baseline a finding
  rests on is real.

## Install

As a Claude Code plugin:

```
/plugin marketplace add kgelster/ecom-cookie-audit
/plugin install cookie-audit@kgelster-cookie
```

For Codex, Cursor, or any other agent that reads `SKILL.md` skills, the
[`skills` CLI](https://agentskills.io) installs it straight from this repo:

```
npx skills add https://github.com/kgelster/ecom-cookie-audit --skill cookie-audit
```

Or manually: clone this repo and copy `skills/cookie-audit/` into your agent's
skills directory.

Script dependencies (any Python 3.10+):

```
pip install playwright pyyaml
playwright install chromium
```

The skill also works analyze-only on HAR files you already have (e.g. supplied
in litigation) — no Playwright needed for that path.

## Usage

See [`skills/cookie-audit/SKILL.md`](skills/cookie-audit/SKILL.md) for the full
procedure. If you installed the skill, ask your agent for an audit and let
`SKILL.md` drive; the commands below are the manual path, run from a clone of
this repo:

```bash
cd skills/cookie-audit
cp config.example.yaml config.yaml   # fill in store URLs
python3 scripts/capture.py --config config.yaml --out captures
python3 scripts/analyze.py --store yourstore.com \
    --har none=captures/none.har --har decline=captures/decline.har \
    --har accept=captures/accept.har --har gpc=captures/gpc.har \
    --out captures/findings.json
python3 scripts/report.py captures/findings.json --out report.md
```

Run captures from a residential connection; datacenter IPs trip bot defenses
(DataDome, Cloudflare) and can change what fires.

## The registry is the product

`vendors.json` is designed to compound: every audit that surfaces an
unclassified host is an opportunity to add it (with verified owner + category)
so the next audit is sharper. PRs that add verified vendor domains or CMP
banner profiles are the most useful contribution. Rules: most-specific domain
wins, verify ownership before adding, and CIPA-sensitive categories
(`analytics`, `ads-pixel`, `session-replay`, `chat`, `email-sms`,
`fraud-fingerprint`) must be right — they drive the exposure section.

The registry is hand-curated and MIT-licensed on purpose. The three richest
tracker databases — DuckDuckGo Tracker Radar, Ghostery TrackerDB, and
Disconnect — are all CC BY-NC-SA (non-commercial), which makes them unusable
in paid audit work without a separate license. The vendor set that matters for
a CIPA report is a few hundred named products, not the whole long tail; a
hand-verified mapping of those is tractable, and one you can actually use
commercially. Do not paste entries from NC-licensed databases into
`vendors.json`; add domains you have verified yourself.

## Prior art & where this fits

Surveyed 2026-08-06. Use these if your need is different; this project exists
for the gap between them.

| Tool | What it does | Consent states | License |
|---|---|---|---|
| [Blacklight collector](https://github.com/the-markup/blacklight-collector) (The Markup) | Best OSS behavioral detection: session recorders, key logging, canvas fingerprinting, pixel events | Single naive load, no banner interaction | GPL-3.0 |
| [Website Evidence Collector](https://code.europa.eu/EDPS/website-evidence-collector) (EDPS) | Regulator-grade evidence capture (cookies, storage, beacons), GDPR/ePrivacy-framed | Single state | EUPL-1.2 |
| [OpenWPM](https://github.com/openwpm/OpenWPM) | Academic web-privacy measurement at crawl scale, Firefox, deep instrumentation | Single state | non-standard |
| [priv-accept](https://github.com/marty90/priv-accept) | Before/after-consent comparison via keyword accept-clicking | Accept only | GPL-3.0 |
| [GPC Web Crawler](https://github.com/privacy-tech-lab/gpc-web-crawler) (privacy-tech-lab) | Sends GPC, re-reads consent values to verify the site honored it; USP/GPP/OneTrust string capture | GPC axis only | MIT |
| [Consent-O-Matic](https://github.com/cavi-au/Consent-O-Matic) | Community-maintained per-CMP banner rulesets (the best map of banner DOM structures) | N/A (extension) | non-standard |
| [CookieBlock Violation Detection](https://github.com/dibollinger/CookieBlock-Violation-Detection) (ETH Zürich) | Declared-vs-observed cookie checks, each paired with a written legal justification (GDPR) | Post-CMP | MIT |
| [haralyzer](https://github.com/haralyzer/haralyzer) | General-purpose Python HAR parsing; no tracker classification | N/A | MIT |
| [DataGrail CIPA Tracker Audit](https://www.datagrail.io/skills/cipa-tracker-audit/) | Free Claude skill: pre-consent + reject-all passes, §631 risk tiers, statutory exposure estimates | Two states | proprietary |

What none of them do, and this project does:

- **Four consent states in one forensic run** — `none`, `decline`, `accept`,
  and `gpc`, each in an isolated context. The legally decisive states
  (pre-consent, post-decline) are the least covered elsewhere.
- **Offline deterministic classification from an artifact.** Every OSS
  classifier runs live in-browser with an adblocker engine attached; nothing
  else takes a HAR and returns vendors, owners, and categories.
- **Shopify consent plumbing.** CMP profiles for the apps Shopify stores
  actually run, and remediation patterns built on
  [`Shopify.customerPrivacy`](https://shopify.dev/docs/api/customer-privacy)
  (the `visitorConsentCollected` event, app-embed gating, GPC region scoping).
- **A commercially usable registry** (see above; the good databases are all
  non-commercial).
- **A strictly diagnostic lane.** Unlike tools that emit risk tiers and
  statutory exposure estimates, this one deliberately stops at observable
  facts mapped to categories for counsel review. That restraint is a feature:
  the report survives scrutiny because it claims nothing it can't prove.

## Legal note

This tool produces technical diagnostics, not legal advice. CIPA litigation
theories (§631 wiretap, §632 recording, §638.51 pen-register) turn on facts and
defenses no network capture can resolve. Use the output with counsel.

## Contributing

PRs welcome. Every PR validates the skill's `SKILL.md` against the
[Agent Skills spec](https://agentskills.io/specification) via
`.github/scripts/validate_skills.py`. Run the same check before you commit with
`git config core.hooksPath .githooks`.

## License

MIT
