import type { Policy } from "./schemas";

type AlertLike = {
  host_id: string;
  created_at: string;
  acknowledged_by: string | null;
  body: { type: string; severity: string; snapshotId?: string | null };
};
type SnapshotLike = {
  id: string;
  host_id: string;
  body: { capturedAt: string; status: string };
};

/** Empty strings match every alert type, host or severity. */
export type AlertFilters = {
  status: "open" | "acknowledged" | "all";
  type: string;
  host: string;
  severity: string;
};
export const defaultAlertFilters: AlertFilters = {
  status: "open",
  type: "",
  host: "",
  severity: "",
};
export function filterAlerts<T extends AlertLike>(
  alerts: T[],
  f: AlertFilters,
): T[] {
  return alerts.filter(
    (a) =>
      (f.status === "all" || (f.status === "open") === !a.acknowledged_by) &&
      (!f.type || a.body.type === f.type) &&
      (!f.host || a.host_id === f.host) &&
      (!f.severity || a.body.severity === f.severity),
  );
}

export type TimelineLink = { tenantId: string; snapshotId: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const prefix = "#timeline?";
/** Shareable hash that reopens the timeline at one snapshot after reload. */
export function timelineHref(link: TimelineLink) {
  return `${prefix}${new URLSearchParams({ tenant: link.tenantId, snapshot: link.snapshotId })}`;
}
export function parseTimelineHref(hash: string): TimelineLink | null {
  if (!hash.startsWith(prefix)) return null;
  const query = new URLSearchParams(hash.slice(prefix.length));
  const tenantId = query.get("tenant")?.toLowerCase() ?? "";
  const snapshotId = query.get("snapshot")?.toLowerCase() ?? "";
  return uuid.test(tenantId) && uuid.test(snapshotId)
    ? { tenantId, snapshotId }
    : null;
}

/** Closest snapshot from the same host by capture time; ties prefer the earlier one. */
export function nearestSnapshot<T extends SnapshotLike>(
  snapshots: T[],
  hostId: string,
  at: string,
): T | null {
  const target = Date.parse(at);
  let best: T | null = null;
  for (const s of snapshots) {
    if (s.host_id !== hostId) continue;
    const distance = Math.abs(Date.parse(s.body.capturedAt) - target);
    const bestDistance = best
      ? Math.abs(Date.parse(best.body.capturedAt) - target)
      : Infinity;
    if (
      distance < bestDistance ||
      (distance === bestDistance &&
        best &&
        Date.parse(s.body.capturedAt) < Date.parse(best.body.capturedAt))
    )
      best = s;
  }
  return best;
}
/** The alert's own snapshot, else the nearest loaded one for its host. */
export function alertSnapshot(
  alert: AlertLike,
  snapshots: SnapshotLike[],
):
  | { snapshotId: string; exact: true }
  | { snapshotId: string; exact: false; capturedAt: string }
  | null {
  if (alert.body.snapshotId)
    return { snapshotId: alert.body.snapshotId, exact: true };
  const near = nearestSnapshot(snapshots, alert.host_id, alert.created_at);
  return near
    ? { snapshotId: near.id, exact: false, capturedAt: near.body.capturedAt }
    : null;
}

export type OnboardingStep = {
  id: "storage" | "keys" | "enrol" | "backup";
  title: string;
  done: boolean;
  status: string;
  commands: string[];
};
const repo = "/absolute/repository",
  hostConfig = "/absolute/host.toml";
/** Checklist state from live tenant data. References only; the host verifies them. */
export function onboardingSteps(state: {
  policies: { body: Policy }[];
  hosts: unknown[];
  snapshots: { body: { status: string } }[];
}): OnboardingStep[] {
  const policy =
    state.policies.find((p) => p.body.hostId === null)?.body ??
    state.policies[0]?.body;
  const backups = state.snapshots.filter(
    (s) => s.body.status === "succeeded",
  ).length;
  return [
    {
      id: "storage",
      title: "Connect storage",
      done: !!policy,
      status: policy
        ? `Policy "${policy.name}" expects ${policy.storage} storage reference "${policy.storageRef}". Set the same storage_ref in the host configuration.`
        : "No policy saved. Save a policy naming the storage reference configured on the host.",
      commands: [
        `# ${hostConfig}: storage_ref = "${policy?.storageRef ?? "STORAGE_REF"}"`,
        `bunker --repo ${repo} replicate --storage /secure/bunker/primary-storage.toml`,
      ],
    },
    {
      id: "keys",
      title: "Set encryption keys",
      done: !!policy,
      status: policy
        ? `Policy expects key reference "${policy.keyRef}". Set the same key_ref in the host configuration.`
        : "No policy saved. Save a policy naming the key reference configured on the host.",
      commands: [
        `# ${hostConfig}: key_ref = "${policy?.keyRef ?? "KEY_REF"}"`,
        `bunker --repo ${repo} --key-config /secure/bunker/keys.toml init`,
      ],
    },
    {
      id: "enrol",
      title: "Enrol the first host",
      done: state.hosts.length > 0,
      status: state.hosts.length
        ? `${state.hosts.length} host${state.hosts.length === 1 ? "" : "s"} enrolled.`
        : "No host enrolled. Create a one-time token, put it in BUNKER_ENROLLMENT_TOKEN on the host, then run the command.",
      commands: [
        `bunker host --config ${hostConfig} enroll --token-env BUNKER_ENROLLMENT_TOKEN`,
      ],
    },
    {
      id: "backup",
      title: "Run the first backup",
      done: backups > 0,
      status: backups
        ? "A host has reported a successful snapshot. Run a sandbox restore test to validate recovery."
        : state.snapshots.length
          ? "Snapshots were reported but none succeeded. Check the host log."
          : "No snapshot reported yet.",
      commands: [
        `bunker --repo ${repo} host --config ${hostConfig} run --workspace /absolute/workspace --once`,
      ],
    },
  ];
}
