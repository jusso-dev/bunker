/** A host report is evidence, not an independent sandbox attestation. */
export type ProbeResult =
  | { outcome: "passed" }
  | { outcome: "failed" | "not_run"; reasonCode: string }
  | { passed: boolean };
export function probeOutcome(
  probe: ProbeResult,
): "passed" | "failed" | "not_run" {
  return "outcome" in probe
    ? probe.outcome
    : probe.passed
      ? "passed"
      : "failed";
}
export function evidenceOutcome(evidence: {
  agents: ProbeResult[];
  mcps: ProbeResult[];
}) {
  const probes = [...evidence.agents, ...evidence.mcps];
  if (probes.some((probe) => probeOutcome(probe) === "failed")) return "failed";
  if (
    !evidence.agents.length ||
    probes.some((probe) => probeOutcome(probe) === "not_run")
  )
    return "not_run";
  return "passed";
}
export type ProbeStat = {
  kind: "agent" | "mcp";
  name: string;
  passed: number;
  failed: number;
  notRun: number;
  /** Newest first. */
  history: {
    reportId: string;
    finishedAt: string;
    outcome: ReturnType<typeof probeOutcome>;
  }[];
};
/** Per-agent and per-MCP results across the given reports. */
export function probeStats(
  reports: {
    id: string;
    body: {
      finishedAt: string;
      agents: (ProbeResult & { agent: string })[];
      mcps: (ProbeResult & { name: string })[];
    };
  }[],
): ProbeStat[] {
  const stats = new Map<string, ProbeStat>();
  const newest = [...reports].sort(
    (a, b) => Date.parse(b.body.finishedAt) - Date.parse(a.body.finishedAt),
  );
  for (const report of newest)
    for (const [kind, name, probe] of [
      ...report.body.agents.map((p) => ["agent", p.agent, p] as const),
      ...report.body.mcps.map((p) => ["mcp", p.name, p] as const),
    ]) {
      const key = `${kind}:${name}`;
      const stat = stats.get(key) ?? {
        kind,
        name,
        passed: 0,
        failed: 0,
        notRun: 0,
        history: [],
      };
      const outcome = probeOutcome(probe);
      stat[outcome === "not_run" ? "notRun" : outcome]++;
      stat.history.push({
        reportId: report.id,
        finishedAt: report.body.finishedAt,
        outcome,
      });
      stats.set(key, stat);
    }
  return [...stats.values()].sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name),
  );
}
/** Skipped checks count against the rate, like the overall report outcome. */
export function passRate(
  stat: Pick<ProbeStat, "passed" | "failed" | "notRun">,
) {
  const total = stat.passed + stat.failed + stat.notRun;
  return total ? stat.passed / total : null;
}
