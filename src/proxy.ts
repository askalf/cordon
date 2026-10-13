import { randomUUID } from "node:crypto";
import { config, adequatePseudonymSecret, allowWeakPseudonymSecret } from "./config";
import { metrics } from "./metrics";
import { getPolicy } from "./policy";
import { adapterFor, forwardUpstream, UpstreamTimeout } from "./providers";
import { detector } from "./detect";
import { applyRedaction, tally } from "./redact/apply";
import { argsFailed, failMessage, reidentifyBody, type ArgStats } from "./redact/reidentify";
import { Vault } from "./redact/vault";
import { captureAndReidentify, pipeUpstream } from "./streaming";
import { audit } from "./audit";
import { nowMs } from "./util";
import { compileSubjects, countMedia, egressViolations, strictestMedia, withSubjects, type CompiledSubjects } from "./subject";
import { maskMedia } from "./media/mask";
import type { CanonicalRequest, HttpRes } from "./types";

/**
 * The spine — the inversion of deja. deja fails OPEN (a cache miss is harmless) and
 * forwards the body verbatim. cordon fails CLOSED (a detection error must block, never
 * leak) and forwards a DE-IDENTIFIED copy. The model never sees raw PII.
 */
export async function handle(r: CanonicalRequest, res: HttpRes) {
  const t0 = nowMs();
  const adapter = adapterFor(r.provider, r.dialect);
  metrics.request(r.mode);
  res.setHeader("X-Redact-Mode", r.mode);

  // A request that names its subjects asked for them to be protected; a policy that turns
  // redaction off cannot honour that, so it is refused rather than passed through.
  if (r.mode === "off" && r.subject)
    return onRedactionError(r, res, new Error("X-Cordon-Subject sent to a tenant whose mode is off"), "closed", t0, "subject");

  // off → transparent passthrough, audited as a bypass.
  if (r.mode === "off") return passthrough(r, res, "mode-off");

  const pol = getPolicy(r.tenant);
  const reportOnly = pol.reportOnly === true;
  const failMode = pol.failMode ?? config.failMode;
  const consistentPseudonyms = pol.consistentPseudonyms ?? config.consistentPseudonyms;
  const redactSystem = pol.redactSystem ?? config.redactSystem;

  // A tenant can enable consistent pseudonyms via /admin/tenant even when the global
  // secret is empty. Minting a keyed token with no adequate secret produces a token
  // anyone can reproduce from the public source (a partial-PII leak), so treat it as a
  // fail-closed misconfiguration for THIS request rather than silently degrading.
  if (consistentPseudonyms && !adequatePseudonymSecret(config.tenantSecret) && !allowWeakPseudonymSecret())
    return onRedactionError(
      r,
      res,
      new Error("consistent pseudonyms enabled without an adequate TENANT_SECRET"),
      failMode,
      t0,
      "pseudonym-secret",
    );

  // ---- detect + redact (fail-closed boundary) ----
  let vault: Vault;
  let deidBody: any;
  let spans;
  let subjects: CompiledSubjects | undefined;
  try {
    if (r.testFail) throw new Error("forced detection failure (test hook)");
    vault = new Vault(r.mode, { consistentPseudonyms, secret: config.tenantSecret });
    subjects = r.subject ? compileSubjects(r.subject, config.tenantSecret) : undefined;
    const det = subjects ? withSubjects(detector, subjects) : detector;
    ({ deidBody, spans } = applyRedaction(r.raw, r.provider, vault, r.activeSets, det, redactSystem, r.dialect));
  } catch (e) {
    // A request that named its subjects is never forwarded raw, whatever the fail mode.
    return onRedactionError(r, res, e, r.subject ? "closed" : failMode, t0);
  }

  const counts = tally(spans);
  metrics.redactions(counts, r.activeSets);

  // ---- known subjects: media, then the egress check on what would actually leave ----
  let egress: string | undefined;
  let egressDetail = "";
  const media = subjects ? countMedia(r.raw) : undefined;
  if (subjects) {
    const mediaMode = strictestMedia(pol.subjectMedia, subjects.media);
    if (media && mediaMode === "block") {
      egress = "media";
      egressDetail = `${media} media part(s) cannot be checked for the subjects' identifiers`;
    } else if (media && mediaMode === "mask") {
      try {
        await maskMedia(deidBody, subjects, r.activeSets, counts);
      } catch (e) {
        egress = "media";
        egressDetail = String((e as any)?.message ?? e);
      }
    }
    if (!egress) {
      try {
        const hits = egressViolations(deidBody, subjects);
        egress = hits.length ? "egress" : "verified";
        if (hits.length) egressDetail = `identifiers still present after redaction: ${hits.join(", ")}`;
      } catch (e) {
        egress = "egress";
        egressDetail = String((e as any)?.message ?? e);
      }
    }
  }

  // ---- audit BEFORE forwarding — counts/types only, never values ----
  let receipt: string | undefined;
  try {
    const rec = await audit.append({
      tenant: r.tenant,
      provider: r.provider,
      model: r.model,
      mode: r.mode,
      entityCounts: counts,
      sets: r.activeSets,
      total: spans.length,
      ...(subjects ? { subject: subjects.refDigest ?? "", egress, media } : {}),
      ...(reportOnly ? { report: true } : {}),
    });
    receipt = rec.hash;
  } catch (e) {
    // A compliance log that can't be written must block in closed mode, and always for a
    // request that named its subjects (its receipt is part of what it asked for).
    if (failMode === "closed" || subjects) return onRedactionError(r, res, e, "closed", t0, "audit");
  }
  if (receipt) res.setHeader("X-Cordon-Receipt", receipt);

  // Report only: the verdict is recorded and returned as headers; the request goes out as
  // the caller sent it (this tenant is being measured, not protected).
  if (reportOnly) {
    res.setHeader("X-Cordon-Report", `redact=${spans.length}${egress ? `; egress=${egress}` : ""}`);
    metrics.bypass("report-only");
    try {
      const up = await forwardUpstream(r);
      await pipeUpstream(up, res);
    } catch (e) {
      safeUpstreamError(res, e);
    }
    metrics.timing("report", t0);
    return;
  }
  if (egress && egress !== "verified") {
    metrics.egressBlocked(egress);
    return onRedactionError(r, res, new Error(egressDetail), "closed", t0, egress);
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
    if (r.mode === "reversible") await captureAndReidentify(up.body, res, adapter, vault, r.provider, r.dialect);
    else await pipeUpstream(up, res); // strip: placeholders persist, verbatim
    metrics.timing("stream", t0);
    return;
  }

  const body = await up.json();
  res.setHeader("content-type", "application/json");
  if (r.mode !== "reversible") {
    res.end(JSON.stringify(body));
    metrics.timing("full", t0);
    return;
  }
  // A placeholder in a tool call's arguments that this request did not mint (a stale one
  // from another conversation, a forged one) would reach the client's tool as data. The
  // call is not delivered: 502 with the count in X-Cordon-Unresolved, the body withheld.
  const stats: ArgStats = { unresolved: 0 };
  const restored = reidentifyBody(body, r.provider, vault, r.dialect, stats);
  if (argsFailed(stats)) {
    res.statusCode = 502;
    res.setHeader("X-Cordon-Unresolved", String(stats.unresolved));
    res.end(JSON.stringify({ error: failMessage(stats) }));
    metrics.timing("error", t0);
    return;
  }
  res.end(JSON.stringify(restored));
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

/**
 * The provider could not be reached (or timed out). The caller gets a fixed message and a
 * request id; the detail (which can name internal hosts, e.g. a residency upstream) goes
 * to the server log only.
 */
export function safeUpstreamError(res: HttpRes, e: unknown) {
  metrics.upstreamError();
  const id = randomUUID();
  const timeout = e instanceof UpstreamTimeout;
  console.error(`[upstream] ${id}: ${String((e as any)?.message ?? e)}`);
  try {
    res.statusCode = timeout ? 504 : 502;
    res.setHeader("content-type", "application/json");
    res.setHeader("X-Request-Id", id);
    res.end(
      JSON.stringify({
        error: `${config.brand}: ${timeout ? "upstream timed out" : "upstream unreachable"}`,
        requestId: id,
      }),
    );
  } catch {
    /* socket already gone */
  }
}
