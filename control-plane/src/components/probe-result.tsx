import { probeOutcome, type ProbeResult } from "../lib/evidence";
export function ProbeResultBadge({ probe }: { probe: ProbeResult }) {
  const outcome = probeOutcome(probe);
  return (
    <>
      <span
        className={`badge ${outcome === "passed" ? "succeeded" : outcome === "failed" ? "failed" : "pending"}`}
      >
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
