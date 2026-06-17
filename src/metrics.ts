// In-memory metrics. The compliance-relevant numbers: redactions by type, mode mix,
// fail-closed count, bypasses. Swap for Prometheus/OTel later.

const s = {
  requests: 0,
  redactedRequests: 0, // requests where ≥1 entity was redacted
  bypass: 0,
  bypassBy: {} as Record<string, number>,
  failClosed: 0,
  upstreamErrors: 0,
  byMode: {} as Record<string, number>, // reversible / strip / off
  byType: {} as Record<string, number>, // entity type → total redacted
  bySet: {} as Record<string, number>, // pii/phi/pci/secrets → total redacted
  redactedEntities: 0,
  lat: {} as Record<string, { n: number; ms: number }>,
};

export const metrics = {
  request(mode: string) {
    s.requests++;
    s.byMode[mode] = (s.byMode[mode] ?? 0) + 1;
  },
  /** Record the entities redacted for one request: { EMAIL: 2, SSN: 1 } and set tallies. */
  redactions(byType: Record<string, number>, sets: string[]) {
    const total = Object.values(byType).reduce((a, b) => a + b, 0);
    if (total > 0) s.redactedRequests++;
    s.redactedEntities += total;
    for (const [t, n] of Object.entries(byType)) s.byType[t] = (s.byType[t] ?? 0) + n;
    for (const set of sets) s.bySet[set] = (s.bySet[set] ?? 0) + total; // coarse: per-request set touch
  },
  bypass(reason = "other") {
    s.bypass++;
    s.bypassBy[reason] = (s.bypassBy[reason] ?? 0) + 1;
  },
  failedClosed() {
    s.failClosed++;
  },
  upstreamError() {
    s.upstreamErrors++;
  },
  timing(src: string, t0: number) {
    const e = s.lat[src] ?? (s.lat[src] = { n: 0, ms: 0 });
    e.n++;
    e.ms += Date.now() - t0;
  },
  report() {
    return {
      requests: s.requests,
      redactedRequests: s.redactedRequests,
      redactedEntities: s.redactedEntities,
      bypass: s.bypass,
      bypassByReason: { ...s.bypassBy },
      failClosed: s.failClosed,
      upstreamErrors: s.upstreamErrors,
      byMode: { ...s.byMode },
      byType: { ...s.byType },
      bySet: { ...s.bySet },
      avgLatencyMs: Object.fromEntries(
        Object.entries(s.lat).map(([k, v]) => [k, +(v.ms / v.n).toFixed(1)]),
      ),
    };
  },
  snapshot() {
    return this.report();
  },
  /** Prometheus text exposition format. */
  prometheus() {
    const r = this.report();
    const L: string[] = [
      `cordon_requests_total ${r.requests}`,
      `cordon_redacted_requests_total ${r.redactedRequests}`,
      `cordon_redacted_entities_total ${r.redactedEntities}`,
      `cordon_bypass_total ${r.bypass}`,
      `cordon_fail_closed_total ${r.failClosed}`,
      `cordon_upstream_errors_total ${r.upstreamErrors}`,
    ];
    for (const [m, n] of Object.entries(r.byMode)) L.push(`cordon_requests_by_mode{mode="${m}"} ${n}`);
    for (const [t, n] of Object.entries(r.byType)) L.push(`cordon_redacted_by_type{type="${t}"} ${n}`);
    for (const [set, n] of Object.entries(r.bySet)) L.push(`cordon_redacted_by_set{set="${set}"} ${n}`);
    for (const [reason, n] of Object.entries(r.bypassByReason)) L.push(`cordon_bypass_by_reason{reason="${reason}"} ${n}`);
    for (const [src, ms] of Object.entries(r.avgLatencyMs)) L.push(`cordon_avg_latency_ms{src="${src}"} ${ms}`);
    return L.join("\n") + "\n";
  },
};
