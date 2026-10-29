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
