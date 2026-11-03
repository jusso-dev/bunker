import test from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { passRate, probeStats } from "../src/lib/evidence";
import { ProbeHistoryTable } from "../src/components/probe-result";
import {
  alertSnapshot,
  defaultAlertFilters,
  filterAlerts,
  nearestSnapshot,
  onboardingSteps,
  parseTimelineHref,
  timelineHref,
} from "../src/lib/console-state";
import { storageProtectionError, type Policy } from "../src/lib/schemas";

const tenant = "11111111-1111-4111-8111-111111111111";
const hostA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const hostB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const snap = (
  id: string,
  host: string,
  capturedAt: string,
  status = "succeeded",
) => ({
  id,
  host_id: host,
  body: { capturedAt, status },
});
const alert = (
  over: Partial<{
    host_id: string;
    created_at: string;
    acknowledged_by: string | null;
    type: string;
    severity: string;
    snapshotId: string | null;
  }> = {},
) => ({
  host_id: over.host_id ?? hostA,
  created_at: over.created_at ?? "2026-11-01T10:00:00Z",
  acknowledged_by: over.acknowledged_by ?? null,
  body: {
    type: over.type ?? "mass-delete",
    severity: over.severity ?? "critical",
    snapshotId: over.snapshotId ?? null,
  },
});

test("restore-test stats give per-agent and per-MCP pass rate and newest-first history", () => {
  const reports = [
    {
      id: "older",
      body: {
        finishedAt: "2026-11-01T00:00:00Z",
        agents: [{ agent: "codex", passed: true }],
        mcps: [
          { name: "github", outcome: "failed" as const, reasonCode: "timeout" },
        ],
      },
    },
    {
      id: "newer",
      body: {
        finishedAt: "2026-11-02T00:00:00Z",
        agents: [
          { agent: "codex", outcome: "passed" as const },
          {
            agent: "cursor",
            outcome: "not_run" as const,
            reasonCode: "runtime_unavailable",
          },
        ],
        mcps: [{ name: "github", outcome: "passed" as const }],
      },
    },
  ];
  const stats = probeStats(reports);
  assert.deepEqual(
    stats.map((s) => `${s.kind}:${s.name}`),
    ["agent:codex", "agent:cursor", "mcp:github"],
  );
  const [codex, cursor, github] = stats;
  assert.deepEqual([codex.passed, codex.failed, codex.notRun], [2, 0, 0]);
  assert.equal(passRate(codex), 1);
  assert.equal(passRate(cursor), 0, "skipped checks never count as passed");
  assert.equal(passRate(github), 0.5);
  assert.deepEqual(
    github.history.map((h) => [h.reportId, h.outcome]),
    [
      ["newer", "passed"],
      ["older", "failed"],
    ],
  );
  assert.equal(passRate({ passed: 0, failed: 0, notRun: 0 }), null);
  const html = renderToStaticMarkup(<ProbeHistoryTable reports={reports} />);
  assert.match(html, /codex.*Agent boot.*100%/);
  assert.match(html, /github.*MCP connection.*50%/);
  assert.match(html, /cursor.*0%.*skip/);
  assert.equal(renderToStaticMarkup(<ProbeHistoryTable reports={[]} />), "");
});

test("alert filters combine status, type, host and severity", () => {
  const alerts = [
    alert(),
    alert({ type: "backup-missed", severity: "warning", host_id: hostB }),
    alert({ acknowledged_by: hostA, type: "force-push" }),
  ];
  assert.equal(filterAlerts(alerts, defaultAlertFilters).length, 2);
  assert.equal(
    filterAlerts(alerts, { ...defaultAlertFilters, status: "acknowledged" })[0],
    alerts[2],
  );
  const all = { ...defaultAlertFilters, status: "all" as const };
  assert.equal(filterAlerts(alerts, all).length, 3);
  assert.deepEqual(filterAlerts(alerts, { ...all, host: hostB }), [alerts[1]]);
  assert.deepEqual(filterAlerts(alerts, { ...all, type: "force-push" }), [
    alerts[2],
  ]);
  assert.deepEqual(filterAlerts(alerts, { ...all, severity: "warning" }), [
    alerts[1],
  ]);
  assert.deepEqual(
    filterAlerts(alerts, { ...all, severity: "critical", host: hostB }),
    [],
  );
});

test("timeline deep links round-trip and reject malformed IDs", () => {
  const snapshotId = "22222222-2222-4222-8222-222222222222";
  const href = timelineHref({ tenantId: tenant, snapshotId });
  assert.equal(href, `#timeline?tenant=${tenant}&snapshot=${snapshotId}`);
  assert.deepEqual(parseTimelineHref(href), { tenantId: tenant, snapshotId });
  assert.deepEqual(
    parseTimelineHref(
      `#timeline?tenant=${tenant.toUpperCase()}&snapshot=${snapshotId.toUpperCase()}`,
    ),
    { tenantId: tenant, snapshotId },
    "UUID case is normalised",
  );
  for (const bad of [
    "",
    "#snapshot-x",
    `#timeline?tenant=${tenant}`,
    `#timeline?tenant=${tenant}&snapshot=not-a-uuid`,
    `#timeline?tenant=../x&snapshot=${snapshotId}`,
  ])
    assert.equal(parseTimelineHref(bad), null, bad);
});

test("alerts link their own snapshot, else the nearest snapshot for that host, else none", () => {
  const snapshots = [
    snap("a-early", hostA, "2026-11-01T09:00:00Z"),
    snap("a-late", hostA, "2026-11-01T10:20:00Z"),
    snap("b-exact", hostB, "2026-11-01T10:00:00Z"),
  ];
  assert.deepEqual(alertSnapshot(alert({ snapshotId: "own" }), snapshots), {
    snapshotId: "own",
    exact: true,
  });
  assert.deepEqual(alertSnapshot(alert({ type: "backup-failed" }), snapshots), {
    snapshotId: "a-late",
    exact: false,
    capturedAt: "2026-11-01T10:20:00Z",
  });
  assert.equal(
    alertSnapshot(
      alert({ host_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }),
      snapshots,
    ),
    null,
    "no cross-host fallback",
  );
  const tie = [
    snap("after", hostA, "2026-11-01T10:10:00Z"),
    snap("before", hostA, "2026-11-01T09:50:00Z"),
  ];
  assert.equal(
    nearestSnapshot(tie, hostA, "2026-11-01T10:00:00Z")?.id,
    "before",
  );
});

test("onboarding checklist follows live policy, host and snapshot state", () => {
  const policy = {
    name: "Default",
    hostId: null,
    storage: "s3",
    storageRef: "primary-bucket",
    keyRef: "org-kms",
  } as Policy;
  const empty = onboardingSteps({ policies: [], hosts: [], snapshots: [] });
  assert.deepEqual(
    empty.map((s) => [s.id, s.done]),
    [
      ["storage", false],
      ["keys", false],
      ["enrol", false],
      ["backup", false],
    ],
  );
  assert.ok(
    empty.every((s) => s.commands.some((c) => c.startsWith("bunker "))),
  );
  assert.match(
    empty[2].commands[0],
    /^bunker host --config \/absolute\/host\.toml enroll --token-env BUNKER_ENROLLMENT_TOKEN$/,
  );
  const failedOnly = onboardingSteps({
    policies: [{ body: policy }],
    hosts: [{}],
    snapshots: [{ body: { status: "failed" } }],
  });
  assert.deepEqual(
    failedOnly.map((s) => s.done),
    [true, true, true, false],
  );
  assert.match(failedOnly[0].commands[0], /storage_ref = "primary-bucket"/);
  assert.match(failedOnly[1].commands[0], /key_ref = "org-kms"/);
  assert.match(failedOnly[3].status, /none succeeded/);
  assert.ok(
    onboardingSteps({
      policies: [{ body: policy }],
      hosts: [{}],
      snapshots: [{ body: { status: "succeeded" } }],
    }).every((s) => s.done),
  );
});

test("consumer and R2 storage cannot request immutability or DR copies", () => {
  for (const storage of ["local", "gdrive", "onedrive", "r2"] as const) {
    assert.match(
      storageProtectionError({ storage, immutable: true, drCopy: false })!,
      /does not support object lock/,
    );
    assert.equal(
      storageProtectionError({ storage, immutable: false, drCopy: false }),
      null,
    );
  }
  for (const storage of ["s3", "azure"] as const)
    assert.equal(
      storageProtectionError({ storage, immutable: true, drCopy: true }),
      null,
    );
  assert.match(
    storageProtectionError({ storage: "s3", immutable: false, drCopy: true })!,
    /requires immutable primary storage/,
  );
});
