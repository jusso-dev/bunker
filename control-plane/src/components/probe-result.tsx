import {
  passRate,
  probeOutcome,
  probeStats,
  type ProbeResult,
} from "../lib/evidence";
const outcomeClass = (outcome: ReturnType<typeof probeOutcome>) =>
  outcome === "passed"
    ? "succeeded"
    : outcome === "failed"
      ? "failed"
      : "pending";
export function ProbeResultBadge({ probe }: { probe: ProbeResult }) {
  const outcome = probeOutcome(probe);
  return (
    <>
      <span className={`badge ${outcomeClass(outcome)}`}>
        {outcome === "not_run" ? "skipped (not run)" : outcome}
      </span>
      {"reasonCode" in probe && (
        <span className="muted">
          {" "}
          · {probe.reasonCode.replaceAll("_", " ")}
        </span>
      )}
    </>
  );
}

export function RestoreProbeScope({ scope }: { scope?: "file-content" }) {
  return (
    <p className="muted">
      {scope === "file-content"
        ? "File-content probes only; Git refs and configuration were not restored."
        : "Probe scope was not reported."}
    </p>
  );
}

/** Pass rate and recent history for each agent and MCP server. */
export function ProbeHistoryTable({
  reports,
  historyLimit = 10,
}: {
  reports: Parameters<typeof probeStats>[0];
  historyLimit?: number;
}) {
  const stats = probeStats(reports);
  if (!stats.length) return null;
  return (
    <table>
      <thead>
        <tr>
          <th>Check</th>
          <th>Pass rate</th>
          <th>Passed / failed / skipped</th>
          <th>Recent history (newest first)</th>
        </tr>
      </thead>
      <tbody>
        {stats.map((stat) => {
          const rate = passRate(stat);
          return (
            <tr key={`${stat.kind}:${stat.name}`}>
              <td>
                {stat.name}
                <small>
                  {stat.kind === "agent" ? "Agent boot" : "MCP connection"}
                </small>
              </td>
              <td>{rate === null ? "—" : `${Math.round(rate * 100)}%`}</td>
              <td>
                {stat.passed} / {stat.failed} / {stat.notRun}
              </td>
              <td>
                {stat.history.slice(0, historyLimit).map((h, i) => (
                  <span
                    key={`${h.reportId}-${i}`}
                    className={`badge ${outcomeClass(h.outcome)}`}
                    title={`${new Date(h.finishedAt).toLocaleString()}: ${h.outcome === "not_run" ? "skipped" : h.outcome}`}
                  >
                    {h.outcome === "passed"
                      ? "pass"
                      : h.outcome === "failed"
                        ? "fail"
                        : "skip"}
                  </span>
                ))}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
