import { config } from "./config";
import { metrics } from "./metrics";
import { getPolicy } from "./policy";
import { adapterFor, forwardUpstream } from "./providers";
import { detector } from "./detect";
import { applyRedaction, tally } from "./redact/apply";
import { reidentifyBody } from "./redact/reidentify";
import { Vault } from "./redact/vault";
import { captureAndReidentify, pipeUpstream } from "./streaming";
import { audit } from "./audit";
import { nowMs } from "./util";
import type { CanonicalRequest, HttpRes } from "./types";

/**
 * The spine — the inversion of deja. deja fails OPEN (a cache miss is harmless) and
 * forwards the body verbatim. cordon fails CLOSED (a detection error must block, never
 * leak) and forwards a DE-IDENTIFIED copy. The model never sees raw PII.
 */
export async function handle(r: CanonicalRequest, res: HttpRes) {
  const t0 = nowMs();
  const adapter = adapterFor(r.provider);
  metrics.request(r.mode);
  res.setHeader("X-Redact-Mode", r.mode);

  // off → transparent passthrough, audited as a bypass.
  if (r.mode === "off") return passthrough(r, res, "mode-off");

  const pol = getPolicy(r.tenant);
  const failMode = pol.failMode ?? config.failMode;
  const consistentPseudonyms = pol.consistentPseudonyms ?? config.consistentPseudonyms;

  // ---- detect + redact (fail-closed boundary) ----
  let vault: Vault;
  let deidBody: any;
  let spans;
  try {
    if (r.testFail) throw new Error("forced detection failure (test hook)");
    vault = new Vault(r.mode, { consistentPseudonyms, secret: config.tenantSecret });
    ({ deidBody, spans } = applyRedaction(r.raw, r.provider, vault, r.activeSets, detector));
  } catch (e) {
    return onRedactionError(r, res, e, failMode, t0);
  }

  const counts = tally(spans);
  metrics.redactions(counts, r.activeSets);

  // ---- audit BEFORE forwarding — counts/types only, never values ----
  try {
    await audit.append({
      tenant: r.tenant,
      provider: r.provider,
      model: r.model,
      mode: r.mode,
      entityCounts: counts,
      sets: r.activeSets,
      total: spans.length,
    });
  } catch (e) {
    // A compliance log that can't be written must block in closed mode.
    if (failMode === "closed") return onRedactionError(r, res, e, failMode, t0, "audit");
  }

  res.setHeader("X-Redacted", String(spans.length));
  if (spans.length)
    res.setHeader(
      "X-Redacted-Types",
      Object.entries(counts)
        .map(([t, n]) => `${t}:${n}`)
        .join(","),
    );

  // ---- forward the DE-IDENTIFIED body upstream ----
  let up: Response;
  try {
    up = await forwardUpstream(r, deidBody);
  } catch (e) {
    return safeUpstreamError(res, e);
  }

  if (!up.ok) {
    // The upstream only ever saw placeholders, so its error body holds no real PII.
    metrics.upstreamError();
    await pipeUpstream(up, res);
    metrics.timing("error", t0);
    return;
  }

  // ---- relay the response (re-identify in reversible mode) ----
  if (r.stream && up.body) {
    if (r.mode === "reversible") await captureAndReidentify(up.body, res, adapter, vault, r.provider);
    else await pipeUpstream(up, res); // strip: placeholders persist, verbatim
    metrics.timing("stream", t0);
    return;
  }

  const body = await up.json();
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(r.mode === "reversible" ? reidentifyBody(body, r.provider, vault) : body));
  metrics.timing("full", t0);
}

/** mode=off (or non-redactable): forward verbatim, record the bypass. */
async function passthrough(r: CanonicalRequest, res: HttpRes, reason: string) {
  metrics.bypass(reason);
  res.setHeader("X-Redacted", "0");
  audit
    .append({
      tenant: r.tenant,
      provider: r.provider,
      model: r.model,
      mode: "off",
      entityCounts: {},
      sets: r.activeSets,
      total: 0,
    })
    .catch(() => {});
  try {
    const up = await forwardUpstream(r); // raw, verbatim
    await pipeUpstream(up, res);
  } catch (e) {
    safeUpstreamError(res, e);
  }
}

/**
 * Detection / audit failure. Default (closed): block with 4xx, upstream NOT called.
 * Open (explicit dev escape hatch): forward the original body, audited as a bypass.
 */
async function onRedactionError(
  r: CanonicalRequest,
  res: HttpRes,
  e: unknown,
  failMode: "closed" | "open",
  t0: number,
  stage = "detect",
) {
  if (failMode === "open") {
    metrics.bypass(`fail-open:${stage}`);
    try {
      const up = await forwardUpstream(r); // ⚠ forwards raw — dev only
      await pipeUpstream(up, res);
    } catch (err) {
      safeUpstreamError(res, err);
    }
    return;
  }
  metrics.failedClosed();
  res.statusCode = 422;
  res.setHeader("content-type", "application/json");
  res.end(
    JSON.stringify({
      error: `${config.brand}: redaction failed at ${stage} — request blocked (fail-closed); upstream not called`,
      detail: String((e as any)?.message ?? e),
    }),
  );
  metrics.timing("fail-closed", t0);
}

function safeUpstreamError(res: HttpRes, e: unknown) {
  metrics.upstreamError();
  try {
    res.statusCode = 502;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: `${config.brand} upstream error: ${String((e as any)?.message ?? e)}` }));
  } catch {
    /* socket already gone */
  }
}
