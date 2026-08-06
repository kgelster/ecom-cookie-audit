# Consent Remediation Runbook (Shopify)

Store-agnostic patterns for gating third-party vendors behind the Shopify consent
banner. Use AFTER a cookie-audit diagnosis, never instead of one.

## Hard boundary (read first)

Diagnosis and options language only. This runbook never authorizes you to:

- Assert a legal classification (strictly-necessary, functional, "violation", HIGH/LOW
  risk). Present the technical basis; the store's counsel makes the call.
- Remediate without explicit approval. Which vendors get gated is a client/counsel
  decision. In practice counsel may name vendors and the merchant may push back on some
  with a functional/security rationale: surface options, wait for the pick.
- Touch a live theme first. Build on a duplicated, unpublished dev theme; publish only
  after client/counsel sign-off.

## Step 0: know what CANNOT be fixed merchant-side

Do not promise a fix that has no merchant control. Three recurring cases (verified
against vendor behavior as of mid-2026; re-verify before relying on them):

- **Klaviyo onsite (US visitors).** Klaviyo honors the Shopify Customer Privacy API only
  in EU/EEA/UK/CH. For US visitors the behavioral beacons (`a.klaviyo.com`,
  `fast.a.klaviyo.com`) fire pre-consent by documented design; there is no Klaviyo
  settings toggle. Only structural fix: disable the app embed and consent-gate a
  re-inject (pattern below).
- **Shopify Google & YouTube channel app (US).** App-pixel consent gating is
  region-based: opt-in regions auto-gate, US opt-out regions fire on Decline with
  Consent Mode v2 signals attached (`gcs=G100`, `npa=1`). "Optimized vs Always on" is
  anti-oversharing, NOT consent gating. Options: uninstall the channel app, replace with
  a Custom Pixel declaring "Required: Analytics", or defend the current state (requests
  carry denied-consent signals and set no `_ga` cookies). Common default: defend.
- **GPC.** Shopify honors `Sec-GPC` automatically but only where the merchant enabled
  the data-sale opt-out region (Settings > Customer privacy). Scope is `sale_of_data`
  only. The fix is the admin toggle, never a theme script calling `setTrackingConsent`
  (ineffective, conflicts with Shopify's handler). Trap: `/.well-known/gpc.json` is
  advertised regardless, so an unconfigured store advertises GPC support it does not
  deliver.

## Vendor triage: pick the right mechanism

For each vendor counsel wants gated, determine HOW its script enters the DOM (read the
HAR initiator chain or view-source):

| Load mechanism | Gate with |
|---|---|
| Dynamic injection (`createElement` + `insertBefore`/`appendChild`), e.g. chat widgets | Hold-and-release interceptor |
| Static `<script src>` rendered server-side (app embeds), e.g. Klaviyo onsite | Disable at source + consent-gated re-inject |
| Shopify app pixel (channel apps) | No theme fix; see Step 0 |
| Piggyback tracker riding on a kept vendor (e.g. a helpdesk app's separate conversion-tag domain) | Permanent BLOCKED list entry |

Parser-inserted static tags are NOT catchable by a DOM-API override. Do not waste a
cycle trying; disable the app embed (`config/settings_data.json`, block
`disabled: true`, same as Theme editor > App embeds toggle) and own the re-inject.
Disabling an embed only stops client-side onsite JS; backend order/profile sync is
unaffected.

## Hold-and-release interceptor pattern

One snippet (e.g. `snippets/consent-deferred-scripts.liquid`), rendered in
`layout/theme.liquid` `<head>` BEFORE `{{ content_for_header }}` so it patches before
vendor bootstraps run.

1. **Hold by default.** Synchronously override `Node.prototype.insertBefore` AND
   `Node.prototype.appendChild`. Two host lists: `GATED` (stash matching `<script src>`
   nodes in a pending array) and `BLOCKED` (drop, never released). Everything else
   passes through to the saved native methods. Hold-by-default guarantees nothing leaks
   in the window before the privacy API resolves.
2. **Consent resolution, three paths.** (a) `Shopify.customerPrivacy.currentVisitorConsent()`
   at load for returning accepted visitors; (b)
   `document.addEventListener('visitorConsentCollected', release)` for the live banner
   click (the event fires on Accept AND Decline, so `release()` must re-check consent);
   (c) a bounded poll for `Shopify.customerPrivacy` availability, since the API is not
   yet present at head time.
3. **Release.** On confirmed consent: set a `released` flag, re-inject each stashed
   script (copy `src`/attributes, in capture order) via the SAVED native `appendChild`,
   and inject any statically-disabled vendors exactly once (guard with a data attribute,
   e.g. `script[data-consent-klaviyo]`).

### The release() regression trap

Do NOT restore the native DOM methods on release. Un-patching makes the permanent
`BLOCKED` list stop working the moment a user accepts, silently regressing any
pre-existing unconditional block the theme carried. Instead: keep the interceptor
installed for the page lifetime and let the `released` flag pass GATED hosts while
BLOCKED stays dropped in both states.

## Per-vendor notes

- **Klaviyo onsite re-inject:** URL shape
  `https://static.klaviyo.com/onsite/js/<COMPANY_ID>/klaviyo.js` (company id from the
  original embed). Stable but merchant-owned once you re-inject; note it in the client
  doc. Pre-consent `_learnq.push` calls buffer in the array shim until the script loads:
  standard Klaviyo behavior, acceptable.
- **Klaviyo host taxonomy (for verify assertions):** `static.klaviyo.com` = CDN script
  delivery, `static-tracking.klaviyo.com` = SDK build, `a.klaviyo.com` /
  `fast.a.klaviyo.com` = the behavioral beacons. Assert on ALL of them in the Decline
  capture; cookie is `__kla_id`.
- **Vendors intentionally not gated** (cart drawer, fraud/bot detection): document the
  functional/security rationale and present it as a push-back option for counsel. Do not
  gate unilaterally, and do not classify them ("strictly necessary" is counsel's word,
  not ours).

## Verify: two-state capture (the only acceptance test)

Run on the dev theme preview, BEFORE publish. Use the skill's own pipeline
(`capture.py --state decline,accept` then `analyze.py` / `report.py --triage`), or a
real-browser capture when the store's bot detection would poison a headless Playwright
fingerprint. If the banner will not re-prompt (consent persisted in an httpOnly
cookie), drive state deterministically with
`Shopify.customerPrivacy.setTrackingConsent({...})`, the same call the banner buttons
make.

- **Decline + PDP + add-to-cart:** zero requests to every gated vendor host (loader
  hosts AND beacon hosts), zero vendor cookies, widget absent.
- **Accept + PDP + add-to-cart:** gated vendors load and function (chat bubble opens,
  vendor cookie set).
- **Both states:** ungated vendors unchanged; add-to-cart and cart drawer work on
  Decline; no new console errors.

Publish only after client/counsel sign-off on the verified dev theme.

## Rollback

Keep it two-line and documented before publish: revert the `layout/theme.liquid` render
(or restore the prior inline blocker) and re-enable the app embed (`disabled: false`).
No data loss.
