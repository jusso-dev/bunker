"use client";

import { evidenceOutcome } from "../lib/evidence";
import {
  ProbeHistoryTable,
  ProbeResultBadge,
  RestoreProbeScope,
} from "./probe-result";
import {
  alertSnapshot,
  defaultAlertFilters,
  filterAlerts,
  onboardingSteps,
  parseTimelineHref,
  timelineHref,
  type AlertFilters,
  type TimelineLink,
} from "../lib/console-state";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { api, apiPage, mergeRows, ClientError, logout } from "../lib/client";
import {
  SnapshotComparison,
  type ComparisonSnapshot,
} from "./snapshot-comparison";
import { Button } from "./ui/button";
import { AccountSettings, RecoveryForm } from "./human-account";
import {
  alert as alertSchema,
  lockCapableStorage,
  storageProtectionError,
  type Policy,
} from "@/lib/schemas";
import type { components } from "../lib/api.generated";
type Tenant = components["schemas"]["meResponse"]["tenants"][number];
type Host = components["schemas"]["hostRow"];
type Snapshot = components["schemas"]["snapshotRow"];
type Restore = components["schemas"]["restoreRow"];
type Alert = components["schemas"]["alertRow"];
type Evidence = components["schemas"]["evidenceRow"];
type PolicyRow = components["schemas"]["policyRow"];
type Data = {
  hosts: Host[];
  snapshots: Snapshot[];
  restores: Restore[];
  alerts: Alert[];
  evidence: Evidence[];
  policies: PolicyRow[];
  notifications: components["schemas"]["notificationRow"][];
  members: components["schemas"]["memberRow"][];
};
const empty: Data = {
  hosts: [],
  snapshots: [],
  restores: [],
  alerts: [],
  evidence: [],
  policies: [],
  notifications: [],
  members: [],
};
const defaults: Policy = {
  name: "Hourly protection",
  hostId: null,
  intervalMinutes: 60,
  endOfSession: true,
  retentionDays: 30,
  exclusions: [
    ".env*",
    "node_modules",
    "dist",
    "transcripts",
    "browser-sessions",
  ],
  sizeCapBytes: 1073741824,
  immutable: false,
  drCopy: false,
  residency: "AU",
  storage: "local",
  storageRef: "local-backup",
  keyRef: "host-key-reference",
  massDeleteThreshold: 25,
  missedBackupMinutes: 90,
  restoreTestIntervalHours: 24,
  channels: ["ui"],
};
const date = (value: string) => new Date(value).toLocaleString();
export function Console() {
  const [tenants, setTenants] = useState<Tenant[]>([]),
    [tenantId, setTenantId] = useState(""),
    [signedIn, setSignedIn] = useState(false),
    [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [transport, setTransport] = useState(""),
    [section, setSection] = useState("Timeline"),
    [data, setData] = useState<Data>(empty),
    [enrollmentToken, setEnrollmentToken] = useState(""),
    [filter, setFilter] = useState(""),
    [alertFilters, setAlertFilters] =
      useState<AlertFilters>(defaultAlertFilters),
    [selected, setSelected] = useState<Restore | null>(null),
    [reviewed, setReviewed] = useState(false),
    [confirmedDigest, setConfirmedDigest] = useState(""),
    [compare, setCompare] = useState<ComparisonSnapshot[]>([]);
  const [cursors, setCursors] = useState<
    Partial<Record<keyof Data, string | null>>
  >({});
  const [tenantCursor, setTenantCursor] = useState<string | null>(null);
  const [localPassword, setLocalPassword] = useState(false);
  const [pinnedSnapshot, setPinnedSnapshot] = useState<Snapshot | null>(null);
  const pageCounts = useRef<Partial<Record<keyof Data, number>>>({});
  const refreshVersion = useRef(0);
  const [identityProviders, setIdentityProviders] = useState<
    components["schemas"]["providersResponse"]
  >([]);
  useEffect(() => {
    let active = true;
    void api<components["schemas"]["providersResponse"]>("auth/providers")
      .then((p) => {
        if (active) setIdentityProviders(p);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);
  const sessionGeneration = useRef(0);
  const openLinkRef = useRef<
    (link: TimelineLink, available: Tenant[]) => Promise<void>
  >(async () => {});
  const clearSession = useCallback(() => {
    sessionGeneration.current += 1;
    setSignedIn(false);
    setTenants([]);
    setTenantId("");
    setTransport("");
    setData(empty);
    setCursors({});
    pageCounts.current = {};
    refreshVersion.current += 1;
    setTenantCursor(null);
    setLocalPassword(false);
    setPinnedSnapshot(null);
    setEnrollmentToken("");
    setSelected(null);
    setReviewed(false);
    setConfirmedDigest("");
    setCompare([]);
    setFilter("");
    setAlertFilters(defaultAlertFilters);
    setSection("Timeline");
    setNotice("");
    setError("");
  }, []);
  const handleError = useCallback(
    (e: unknown) => {
      if (e instanceof ClientError && e.status === 401) clearSession();
      setError(e instanceof Error ? e.message : "Request failed");
    },
    [clearSession],
  );
  const tenant = tenants.find((t) => t.id === tenantId),
    canEdit = ["admin", "operator"].includes(tenant?.role ?? ""),
    canApprove = ["admin", "approver"].includes(tenant?.role ?? "");
  const loadMe = useCallback(async () => {
    const generation = sessionGeneration.current;
    try {
      const { data: me, next } =
        await apiPage<components["schemas"]["meResponse"]>("me");
      if (generation !== sessionGeneration.current) return;
      setTenants(me.tenants);
      setTenantCursor(next);
      setLocalPassword(me.localPassword);
      setTenantId((current) =>
        me.tenants.some((x) => x.id === current)
          ? current
          : (me.tenants[0]?.id ?? ""),
      );
      setTransport(me.hostTransport);
      setSignedIn(true);
      return me.tenants;
    } catch (e) {
      handleError(e);
    } finally {
      setLoading(false);
    }
  }, [handleError]);
  useEffect(() => {
    let active = true;
    const generation = sessionGeneration.current;
    void apiPage<components["schemas"]["meResponse"]>("me")
      .then(({ data: me, next }) => {
        if (!active || generation !== sessionGeneration.current) return;
        setTenants(me.tenants);
        setTenantCursor(next);
        setLocalPassword(me.localPassword);
        setTenantId(me.tenants[0]?.id ?? "");
        setTransport(me.hostTransport);
        setSignedIn(true);
        const link = parseTimelineHref(window.location.hash);
        if (link) void openLinkRef.current(link, me.tenants);
      })
      .catch((e) => {
        if (active && generation === sessionGeneration.current) handleError(e);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [handleError]);
  const refresh = useCallback(async () => {
    if (!tenantId) return;
    const keys: (keyof Data)[] = [
      "hosts",
      "snapshots",
      "restores",
      "alerts",
      "evidence",
      "policies",
      "notifications",
    ];
    if (tenant?.role === "admin") keys.push("members");
    const result = await Promise.all(
      keys.map(async (key) => {
        let rows: { id: string }[] = [],
          next: string | null = null;
        // Rebuild each loaded prefix on refresh, following fresh cursors. This
        // updates old approvals/members and cannot bridge over an unseen gap.
        for (let i = 0; i < (pageCounts.current[key] ?? 1); i++) {
          const page: { data: { id: string }[]; next: string | null } =
            await apiPage(`tenants/${tenantId}/${key}`, next);
          rows = mergeRows(rows, page.data);
          next = page.next;
          if (!next) break;
        }
        return { key, rows, next };
      }),
    );
    return {
      data: {
        ...empty,
        ...Object.fromEntries(result.map((r) => [r.key, r.rows])),
      } as Data,
      cursors: Object.fromEntries(result.map((r) => [r.key, r.next])),
    };
  }, [tenantId, tenant?.role]);
  useEffect(() => {
    if (!signedIn || !tenantId) return;
    let active = true;
    const generation = sessionGeneration.current;
    const tick = async () => {
      try {
        const version = ++refreshVersion.current;
        const next = await refresh();
        if (
          active &&
          generation === sessionGeneration.current &&
          next &&
          version === refreshVersion.current
        ) {
          setData(next.data);
          setCursors(next.cursors);
        }
      } catch (e) {
        if (active && generation === sessionGeneration.current) {
          if (e instanceof ClientError && e.status === 403) {
            sessionGeneration.current += 1;
            setData(empty);
            setCursors({});
            pageCounts.current = {};
            setCompare([]);
            setSelected(null);
            setPinnedSnapshot(null);
            setEnrollmentToken("");
            setTenantId("");
            await loadMe();
          }
          handleError(e);
        }
      }
    };
    void tick();
    const timer = setInterval(tick, 15000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [refresh, signedIn, tenantId, handleError, loadMe]);
  function switchTenant(id: string) {
    sessionGeneration.current += 1;
    setTenantId(id);
    setData(empty);
    setCursors({});
    pageCounts.current = {};
    refreshVersion.current += 1;
    setPinnedSnapshot(null);
    setSelected(null);
    setEnrollmentToken("");
    setCompare([]);
    setAlertFilters((f) => ({ ...f, host: "" }));
    setNotice("");
    setError("");
  }
  // Shareable timeline links (#timeline?tenant=…&snapshot=…) survive reloads.
  async function openTimelineLink(link: TimelineLink, available: Tenant[]) {
    setError("");
    setNotice("");
    if (!available.some((t) => t.id === link.tenantId)) {
      setError("The linked snapshot belongs to a tenant you cannot access.");
      return;
    }
    if (link.tenantId !== tenantId) switchTenant(link.tenantId);
    setSection("Timeline");
    setSelected(null);
    const generation = sessionGeneration.current;
    try {
      const rows = await api<Snapshot[]>(
        `tenants/${link.tenantId}/snapshots/${link.snapshotId}`,
      );
      if (generation !== sessionGeneration.current) return;
      if (!rows[0]) throw new Error("Snapshot no longer available");
      setPinnedSnapshot(rows[0]);
      setFilter(rows[0].id);
    } catch (e) {
      if (generation === sessionGeneration.current) handleError(e);
    }
  }
  useEffect(() => {
    openLinkRef.current = openTimelineLink;
  });
  useEffect(() => {
    const onPop = () => {
      const link = parseTimelineHref(window.location.hash);
      if (link) void openLinkRef.current(link, tenants);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [tenants]);
  async function run(fn: () => Promise<void>) {
    const generation = sessionGeneration.current;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      if (generation === sessionGeneration.current) handleError(e);
    } finally {
      setBusy(false);
    }
  }
  async function mutate(path: string, payload: unknown) {
    const generation = sessionGeneration.current;
    await api(`tenants/${tenantId}/${path}`, payload);
    const version = ++refreshVersion.current;
    const next = await refresh();
    if (
      generation !== sessionGeneration.current ||
      version !== refreshVersion.current
    )
      return;
    if (next) {
      setData(next.data);
      setCursors(next.cursors);
    }
    setNotice("Saved.");
  }
  async function loadMore(key: keyof Data) {
    const cursor = cursors[key];
    if (!cursor) return;
    const generation = sessionGeneration.current;
    refreshVersion.current += 1;
    const page = await apiPage<{ id: string }[]>(
      `tenants/${tenantId}/${key}`,
      cursor,
    );
    if (generation !== sessionGeneration.current) return;
    refreshVersion.current += 1;
    pageCounts.current[key] = (pageCounts.current[key] ?? 1) + 1;
    setData((current) => ({
      ...current,
      [key]: mergeRows(current[key], page.data),
    }));
    setCursors((current) => ({ ...current, [key]: page.next }));
  }
  if (loading)
    return (
      <main className="signin">
        <p role="status">Opening Bunker…</p>
      </main>
    );
  if (!signedIn)
    return (
      <main className="signin">
        <div className="wordmark">
          BUNKER<span>RECOVERY CONTROL</span>
        </div>
        <h1>Keep a way back.</h1>
        <p>Sign in to manage protection and review recovery requests.</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            void run(async () => {
              await api("auth/login", {
                email: f.get("email"),
                password: f.get("password"),
              });
              const available = await loadMe();
              const link = parseTimelineHref(window.location.hash);
              if (link && available) await openLinkRef.current(link, available);
            });
          }}
        >
          <label>
            Email
            <input name="email" type="email" autoComplete="username" required />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
              maxLength={256}
            />
          </label>
          <Button disabled={busy}>Sign in</Button>
        </form>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {identityProviders.map((p) => (
          <Button
            key={p.id}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const result = await api<
                  components["schemas"]["federatedStartResponse"]
                >(`auth/federated/${p.id}/start`, {});
                window.location.assign(result.authorizationUrl);
              })
            }
          >
            Sign in with {p.name}
          </Button>
        ))}
        {notice && <p role="status">{notice}</p>}
        <RecoveryForm
          busy={busy}
          run={run}
          done={() => {
            clearSession();
            setNotice("Password recovered. Sign in with your new password.");
          }}
        />
        <p className="muted">
          Federated identities must be linked by your administrator.
        </p>
      </main>
    );
  const loadedSnapshots = mergeRows(
    data.snapshots,
    pinnedSnapshot ? [pinnedSnapshot] : [],
  );
  const visible = loadedSnapshots.filter((s) =>
    [s.id, s.host_id, s.body.agent, s.body.sessionId].some((v) =>
      v.includes(filter),
    ),
  );
  const passed = data.evidence.filter(
    (e) => evidenceOutcome(e.body) === "passed",
  ).length;
  const steps = onboardingSteps(data);
  const nextStep = steps.findIndex((step) => !step.done);
  return (
    <div className="shell">
      <aside>
        <div className="wordmark">
          BUNKER<span>RECOVERY CONTROL</span>
        </div>
        <label className="tenant-label">
          Client tenant
          <select
            disabled={busy}
            value={tenantId}
            onChange={(e) => switchTenant(e.target.value)}
          >
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
        {tenantCursor && (
          <Button
            disabled={busy}
            variant="outline"
            onClick={() =>
              void run(async () => {
                const generation = sessionGeneration.current;
                const page = await apiPage<components["schemas"]["meResponse"]>(
                  "me",
                  tenantCursor,
                );
                if (generation !== sessionGeneration.current) return;
                setTenants((current) => mergeRows(current, page.data.tenants));
                setTenantCursor(page.next);
              })
            }
          >
            Load more tenants
          </Button>
        )}
        <small>{tenant?.role}</small>
        <nav aria-label="Main navigation">
          {[
            "Timeline",
            "Approvals",
            "Policies",
            "Onboarding",
            "Alerts",
            "Restore tests",
            "Administration",
            "Account",
          ].map((item) => (
            <button
              key={item}
              aria-current={section === item ? "page" : undefined}
              onClick={() => {
                if (parseTimelineHref(window.location.hash))
                  window.history.replaceState(
                    null,
                    "",
                    window.location.pathname + window.location.search,
                  );
                setSection(item);
                setSelected(null);
                setNotice("");
              }}
            >
              {item}
              {item === "Approvals" && (
                <span>
                  {data.restores.filter((x) => x.status === "pending").length}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="aside-bottom">
          <p>
            Encrypted on your host.
            <br />
            Metadata in your control plane.
          </p>
          <button
            onClick={() =>
              void run(async () => {
                await logout(clearSession);
              })
            }
          >
            Sign out
          </button>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">{tenant?.name} / Protection</p>
            <h1>{section}</h1>
          </div>
          {tenantId && (
            <a
              className="button outline"
              href={`/api/tenants/${tenantId}/export`}
            >
              Export evidence ↓
            </a>
          )}
        </header>
        {!tenantId && (
          <p>
            No tenant access is assigned. Your account settings remain
            available.
          </p>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {notice && (
          <p className="success" role="status">
            {notice}
          </p>
        )}
        {section === "Timeline" && (
          <>
            <div className="summary">
              <div>
                <strong>{data.hosts.length}</strong>
                <span>Enrolled hosts</span>
              </div>
              <div>
                <strong>{data.snapshots.length}</strong>
                <span>Recent snapshots</span>
              </div>
              <div>
                <strong>
                  {data.alerts.filter((x) => !x.acknowledged_by).length}
                </strong>
                <span>Open alerts</span>
              </div>
            </div>
            <div className="toolbar">
              <label>
                Find a snapshot
                <input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Host ID, agent, session or snapshot ID"
                />
              </label>
              <span className="muted">
                Loaded history · refreshes every 15 seconds · load more below
              </span>
            </div>
            <SnapshotComparison
              snapshots={compare}
              onClear={() => setCompare([])}
            />
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Compare</th>
                    <th>Captured</th>
                    <th>Agent / session</th>
                    <th>Snapshot</th>
                    <th>Files</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((s) => (
                    <tr key={s.id} id={`snapshot-${s.id}`}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Compare snapshot ${s.id}`}
                          checked={compare.some((row) => row.id === s.id)}
                          disabled={
                            !compare.some((row) => row.id === s.id) &&
                            compare.length === 2
                          }
                          onChange={(e) =>
                            setCompare(
                              e.target.checked
                                ? [...compare, s]
                                : compare.filter((row) => row.id !== s.id),
                            )
                          }
                        />
                      </td>
                      <td>
                        {date(s.body.capturedAt)}
                        <small>
                          {data.hosts.find((h) => h.id === s.host_id)?.name ??
                            s.host_id}
                        </small>
                      </td>
                      <td>
                        {s.body.agent}
                        <small>{s.body.sessionId}</small>
                      </td>
                      <td>
                        <code>{s.id}</code>
                      </td>
                      <td>{s.body.fileCount}</td>
                      <td>
                        <span className={`badge ${s.body.status}`}>
                          {s.body.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {visible.length === 0 && (
              <Empty title="No snapshots yet">
                Enroll a host and configure its local storage to start reporting
                backups.
              </Empty>
            )}
            <p className="muted">
              To restore a file, session, or workspace, request a diff from the
              local daemon. Its metadata and approval request appear in
              Approvals.
            </p>
          </>
        )}
        {section === "Approvals" && (
          <>
            <p>
              Every approval is tied to one immutable diff digest and expires
              after 15 minutes. Review the decrypted diff on the host before
              approving. This UI records approval; it does not execute a local
              restore. A daemon bridge must claim the approval and perform the
              restore.
            </p>
            {data.restores.length === 0 && (
              <Empty title="No recovery requests">
                Host requests appear here for independent human review.
              </Empty>
            )}
            {data.restores.map((r) => (
              <section className="row" key={r.id}>
                <div>
                  <strong>{r.body.kind} restore</strong>
                  <small>
                    {r.id} · expires {date(r.expires_at)}
                  </small>
                </div>
                <span className={`badge ${r.status}`}>{r.status}</span>
                <Button
                  variant="outline"
                  onClick={() => {
                    setSelected(r);
                    setReviewed(false);
                    setConfirmedDigest("");
                  }}
                >
                  Review diff metadata
                </Button>
              </section>
            ))}
            {selected && (
              <section className="panel">
                <h2>Review {selected.body.kind} restore</h2>
                <p>
                  Snapshot <code>{selected.body.snapshotId}</code>
                </p>
                <p>
                  Diff digest <code>{selected.body.diffDigest}</code>
                </p>
                <table>
                  <thead>
                    <tr>
                      <th>Opaque file ID</th>
                      <th>Change</th>
                      <th>Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.body.changes.map((c) => (
                      <tr key={c.fileId}>
                        <td>
                          <code>{c.fileId}</code>
                          <small>
                            Before: {c.beforeDigest ?? "absent"}
                            <br />
                            After: {c.afterDigest ?? "absent"}
                          </small>
                        </td>
                        <td>{c.action}</td>
                        <td>{c.bytes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={reviewed}
                    onChange={(e) => setReviewed(e.target.checked)}
                  />
                  I reviewed the decrypted diff on the host and confirmed the
                  destination state.
                </label>
                <label>
                  Paste the diff digest displayed by the local daemon
                  <input
                    value={confirmedDigest}
                    onChange={(e) => setConfirmedDigest(e.target.value)}
                    autoComplete="off"
                  />
                </label>
                <div className="actions">
                  <Button
                    disabled={
                      busy ||
                      !canApprove ||
                      !reviewed ||
                      confirmedDigest !== selected.body.diffDigest ||
                      selected.status !== "pending"
                    }
                    onClick={() =>
                      void run(async () => {
                        await mutate(`restores/${selected.id}/decision`, {
                          decision: "approve",
                          diffDigest: confirmedDigest,
                          reviewedLocalDiff: reviewed,
                        });
                        setSelected(null);
                      })
                    }
                  >
                    Approve once
                  </Button>
                  <Button
                    variant="destructive"
                    disabled={
                      busy || !canApprove || selected.status !== "pending"
                    }
                    onClick={() =>
                      void run(async () => {
                        await mutate(`restores/${selected.id}/decision`, {
                          decision: "deny",
                          diffDigest: selected.body.diffDigest,
                          reviewedLocalDiff: false,
                        });
                        setSelected(null);
                      })
                    }
                  >
                    Deny
                  </Button>
                </div>
                {!canApprove && (
                  <p className="muted">
                    An approver or administrator must make this decision.
                  </p>
                )}
              </section>
            )}
          </>
        )}
        {section === "Policies" && (
          <>
            <p>
              Tenant defaults apply unless a host has an override. Hosts should
              poll every 30 seconds. Storage and key references resolve locally;
              never enter credentials here.
            </p>
            <PolicyEditor
              key={`${tenantId}-${data.policies.map((p) => p.version).join("-")}`}
              policies={data.policies}
              hosts={data.hosts}
              disabled={!canEdit || busy}
              save={(p) => run(() => mutate("policies", p))}
            />
          </>
        )}
        {section === "Onboarding" && (
          <section className="panel">
            <h2>Setup checklist</h2>
            <p className="muted">
              {steps.filter((step) => step.done).length} of {steps.length}{" "}
              complete. Steps follow live tenant data and refresh every 15
              seconds. The control plane stores storage and key reference names
              only; the host checks connectivity, object lock, escrow and
              residency when it runs.
            </p>
            <ol className="checklist">
              {steps.map((step, i) => (
                <li
                  key={step.id}
                  aria-current={i === nextStep ? "step" : undefined}
                >
                  <div className="step-heading">
                    <strong>
                      {i + 1}. {step.title}
                    </strong>
                    <span
                      className={`badge ${step.done ? "succeeded" : "pending"}`}
                    >
                      {step.done ? "Done" : i === nextStep ? "Next" : "To do"}
                    </span>
                  </div>
                  <p>{step.status}</p>
                  <pre>
                    <code>{step.commands.join("\n")}</code>
                  </pre>
                  {(step.id === "storage" || step.id === "keys") && (
                    <Button
                      variant="outline"
                      onClick={() => setSection("Policies")}
                    >
                      Set policy references
                    </Button>
                  )}
                  {step.id === "enrol" && (
                    <>
                      <p>
                        {transport === "development-loopback"
                          ? "Development loopback enrollment is enabled. Tokens expire after 10 minutes and can be used once."
                          : transport === "mtls"
                            ? "One-time tokens expire after 10 minutes. Your host generates its own key and CSR and receives a certificate for the mTLS endpoint."
                            : "Production gateway is not configured."}
                      </p>
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          const f = new FormData(e.currentTarget);
                          void run(async () => {
                            const generation = sessionGeneration.current;
                            const result = await api<
                              components["schemas"]["enrollmentResponse"]
                            >(`tenants/${tenantId}/enrollments`, {
                              name: f.get("name"),
                            });
                            if (generation !== sessionGeneration.current)
                              return;
                            setEnrollmentToken(result.token);
                          });
                        }}
                      >
                        <label>
                          Host name
                          <input name="name" required maxLength={100} />
                        </label>
                        <Button
                          disabled={
                            busy ||
                            !canEdit ||
                            !["development-loopback", "mtls"].includes(
                              transport,
                            )
                          }
                        >
                          Create one-time token
                        </Button>
                      </form>
                      {enrollmentToken && (
                        <div className="secret">
                          <p>
                            Put this in BUNKER_ENROLLMENT_TOKEN on the host. It
                            will not be shown again after leaving this tenant or
                            signing out.
                          </p>
                          <code>{enrollmentToken}</code>
                          <Button
                            variant="outline"
                            onClick={() => setEnrollmentToken("")}
                          >
                            Hide token
                          </Button>
                        </div>
                      )}
                    </>
                  )}
                  {step.id === "backup" && (
                    <Button
                      variant="outline"
                      onClick={() => setSection("Timeline")}
                    >
                      Open timeline
                    </Button>
                  )}
                </li>
              ))}
            </ol>
          </section>
        )}
        {section === "Alerts" && (
          <>
            <div className="toolbar">
              <label>
                Show
                <select
                  value={alertFilters.status}
                  onChange={(e) =>
                    setAlertFilters((f) => ({
                      ...f,
                      status: e.target.value as AlertFilters["status"],
                    }))
                  }
                >
                  <option value="open">Open</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="all">All alerts</option>
                </select>
              </label>
              <label>
                Type
                <select
                  value={alertFilters.type}
                  onChange={(e) =>
                    setAlertFilters((f) => ({ ...f, type: e.target.value }))
                  }
                >
                  <option value="">All types</option>
                  {alertSchema.shape.type.options.map((type) => (
                    <option key={type} value={type}>
                      {type.replaceAll("-", " ")}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Host
                <select
                  value={alertFilters.host}
                  onChange={(e) =>
                    setAlertFilters((f) => ({ ...f, host: e.target.value }))
                  }
                >
                  <option value="">All hosts</option>
                  {data.hosts.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Severity
                <select
                  value={alertFilters.severity}
                  onChange={(e) =>
                    setAlertFilters((f) => ({
                      ...f,
                      severity: e.target.value,
                    }))
                  }
                >
                  <option value="">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="warning">Warning</option>
                </select>
              </label>
              <p className="muted">
                Filters apply to loaded alerts. UI delivery is always enabled.
                Webhooks require operator provisioning and policy opt-in.
              </p>
            </div>
            {filterAlerts(data.alerts, alertFilters).map((a) => {
              const target = alertSnapshot(a, loadedSnapshots);
              const link = target && {
                tenantId,
                snapshotId: target.snapshotId,
              };
              return (
                <section className="row" key={a.id}>
                  <div>
                    <strong>{a.body.type.replaceAll("-", " ")}</strong>
                    <small>
                      {date(a.created_at)} ·{" "}
                      {data.hosts.find((h) => h.id === a.host_id)?.name ??
                        a.host_id}{" "}
                      · {a.occurrences} reports · {a.body.count} affected
                    </small>
                    <small>
                      {(() => {
                        const delivery = data.notifications.find(
                          (n) => n.alert_id === a.id,
                        );
                        return delivery
                          ? `Webhook: ${delivery.state} · ${delivery.attempts}/8 attempts${delivery.last_error ? ` · ${delivery.last_error}` : ""}`
                          : "No webhook delivery in loaded history";
                      })()}
                    </small>
                    {link ? (
                      <a
                        href={timelineHref(link)}
                        onClick={(event) => {
                          event.preventDefault();
                          window.history.pushState(
                            null,
                            "",
                            timelineHref(link),
                          );
                          void openTimelineLink(link, tenants);
                        }}
                      >
                        {target.exact
                          ? "Open snapshot in timeline"
                          : `No snapshot on this alert · open nearest for this host (captured ${date(target.capturedAt)})`}
                      </a>
                    ) : (
                      <small>
                        No snapshot for this host in loaded history. Load more
                        snapshots on the Timeline to search further back.
                      </small>
                    )}
                  </div>
                  <span className="badge">{a.body.severity}</span>
                  <Button
                    variant="outline"
                    disabled={busy || !canEdit || !!a.acknowledged_by}
                    onClick={() =>
                      void run(() => mutate(`alerts/${a.id}/acknowledge`, {}))
                    }
                  >
                    {a.acknowledged_by ? "Acknowledged" : "Acknowledge"}
                  </Button>
                </section>
              );
            })}
            {data.alerts.length === 0 ? (
              <Empty title="No alerts reported">
                Detections from enrolled hosts will appear here.
              </Empty>
            ) : (
              filterAlerts(data.alerts, alertFilters).length === 0 && (
                <Empty title="No alerts match these filters">
                  Change the filters or load more alerts.
                </Empty>
              )
            )}
          </>
        )}
        {section === "Restore tests" && (
          <>
            <div className="summary">
              <div>
                <strong>
                  {data.evidence.length
                    ? `${Math.round((passed / data.evidence.length) * 100)}%`
                    : "—"}
                </strong>
                <span>Fully passed reports (skipped checks do not pass)</span>
              </div>
              <div>
                <strong>{data.evidence.length}</strong>
                <span>Recent test reports</span>
              </div>
            </div>
            <p>
              Evidence is reported by the host. It does not independently attest
              that a sandbox was isolated or cloud recovery succeeded.
            </p>
            {data.evidence.length > 0 && (
              <section className="panel">
                <h2>By agent and MCP server</h2>
                <p className="muted">
                  Across loaded reports. Skipped checks count as not passed.
                </p>
                <ProbeHistoryTable reports={data.evidence} />
              </section>
            )}
            {data.evidence.map((e) => (
              <section className="panel" key={e.id}>
                <h2>{date(e.body.finishedAt)}</h2>
                <p>
                  {e.body.sandbox} · snapshot <code>{e.snapshot_id}</code>
                </p>
                <RestoreProbeScope scope={e.body.scope} />
                {e.body.agents.map((x) => (
                  <p key={x.agent}>
                    {x.agent} boot <ProbeResultBadge probe={x} />
                  </p>
                ))}
                {e.body.mcps.map((x) => (
                  <p key={x.name}>
                    {x.name} connection <ProbeResultBadge probe={x} />
                  </p>
                ))}
                {e.body.mcps.length === 0 && (
                  <p>No MCP checks were reported.</p>
                )}
              </section>
            ))}
            {data.evidence.length === 0 && (
              <Empty title="Recovery is not yet verified">
                Run a scheduled sandbox restore on the host to collect agent
                boot and MCP connection evidence.
              </Empty>
            )}
          </>
        )}
        {section === "Account" && (
          <AccountSettings
            localPassword={localPassword}
            clearSession={clearSession}
            onError={handleError}
          />
        )}
        {section === "Administration" && (
          <>
            {tenant?.role !== "admin" ? (
              <p>Tenant administration requires the administrator role.</p>
            ) : (
              <>
                <section className="panel">
                  <h2>Add a client tenant</h2>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      const f = new FormData(e.currentTarget);
                      void run(async () => {
                        await api(`tenants/${tenantId}/tenants`, {
                          name: f.get("name"),
                        });
                        await loadMe();
                        setNotice(
                          "Tenant created. Select it from the tenant menu.",
                        );
                      });
                    }}
                  >
                    <label>
                      Tenant name
                      <input name="name" required maxLength={100} />
                    </label>
                    <Button disabled={busy}>Create tenant</Button>
                  </form>
                </section>
                <section className="panel">
                  <h2>Tenant members</h2>
                  <p>
                    Removal takes effect immediately for this tenant. The last
                    administrator cannot be removed.
                  </p>
                  {data.members.map((member) => (
                    <div className="row" key={member.id}>
                      <div>
                        <strong>{member.email}</strong>
                        <small>{member.role}</small>
                      </div>
                      <Button
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          void run(async () => {
                            await api(
                              `tenants/${tenantId}/members/${member.id}/revoke`,
                              {},
                            );
                            // Refresh /me after self-removal; never retain revoked tenant data.
                            sessionGeneration.current += 1;
                            setData(empty);
                            setCursors({});
                            pageCounts.current = {};
                            setCompare([]);
                            setSelected(null);
                            setPinnedSnapshot(null);
                            setEnrollmentToken("");
                            setTenantId("");
                            await loadMe();
                            setNotice("Tenant access removed.");
                          })
                        }
                      >
                        Remove access for {member.email}
                      </Button>
                    </div>
                  ))}
                  {cursors.members && (
                    <Button
                      variant="outline"
                      disabled={busy}
                      onClick={() => void run(() => loadMore("members"))}
                    >
                      Load more members
                    </Button>
                  )}
                </section>
                <section className="panel">
                  <h2>Grant tenant access</h2>
                  <p>
                    Existing users keep their password. Supply an initial
                    password only for a new local account.
                  </p>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      const f = new FormData(e.currentTarget);
                      const form = e.currentTarget;
                      void run(async () => {
                        await mutate("members", {
                          email: f.get("email"),
                          role: f.get("role"),
                          ...(f.get("password")
                            ? { password: f.get("password") }
                            : {}),
                        });
                        form.reset();
                      });
                    }}
                  >
                    <label>
                      Email
                      <input
                        name="email"
                        type="email"
                        required
                        autoComplete="off"
                      />
                    </label>
                    <label>
                      Initial password
                      <input
                        name="password"
                        type="password"
                        minLength={14}
                        maxLength={256}
                        autoComplete="new-password"
                      />
                    </label>
                    <label>
                      Role
                      <select name="role">
                        <option>viewer</option>
                        <option>operator</option>
                        <option>approver</option>
                        <option>admin</option>
                      </select>
                    </label>
                    <Button disabled={busy}>Grant access</Button>
                  </form>
                </section>
              </>
            )}
          </>
        )}
        {section === "Timeline" && cursors.snapshots && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void run(() => loadMore("snapshots"))}
          >
            Load more snapshots
          </Button>
        )}
        {section === "Approvals" && cursors.restores && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void run(() => loadMore("restores"))}
          >
            Load more approvals
          </Button>
        )}
        {section === "Policies" && (
          <>
            {cursors.policies && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void run(() => loadMore("policies"))}
              >
                Load more policies
              </Button>
            )}
            {cursors.hosts && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void run(() => loadMore("hosts"))}
              >
                Load more hosts
              </Button>
            )}
          </>
        )}
        {section === "Onboarding" && cursors.hosts && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void run(() => loadMore("hosts"))}
          >
            Load more hosts
          </Button>
        )}
        {section === "Alerts" && (
          <>
            {cursors.alerts && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void run(() => loadMore("alerts"))}
              >
                Load more alerts
              </Button>
            )}
            {cursors.notifications && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void run(() => loadMore("notifications"))}
              >
                Load more webhook deliveries
              </Button>
            )}
          </>
        )}
        {section === "Restore tests" && cursors.evidence && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void run(() => loadMore("evidence"))}
          >
            Load more test reports
          </Button>
        )}
      </main>
    </div>
  );
}
function Empty({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
function PolicyEditor({
  policies,
  hosts,
  disabled,
  save,
}: {
  policies: PolicyRow[];
  hosts: Host[];
  disabled: boolean;
  save: (p: Policy) => Promise<void>;
}) {
  const [policy, setPolicy] = useState<Policy>(
    policies.find((p) => p.body.hostId === null)?.body ?? defaults,
  );
  const set = <K extends keyof Policy>(key: K, value: Policy[K]) =>
    setPolicy((p) => ({ ...p, [key]: value }));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void save(policy);
  };
  const protectionError = storageProtectionError(policy);
  return (
    <form className="panel policy" onSubmit={submit}>
      <fieldset disabled={disabled}>
        <legend>Protection policy</legend>
        <label>
          <input
            type="checkbox"
            checked={policy.channels.includes("webhook")}
            onChange={(e) =>
              set("channels", e.target.checked ? ["ui", "webhook"] : ["ui"])
            }
          />
          Send new alerts to the operator-provisioned webhook
        </label>
        <div className="form-grid">
          <label>
            Scope
            <select
              value={policy.hostId ?? ""}
              onChange={(e) => {
                const hostId = e.target.value || null;
                setPolicy(
                  policies.find((p) => p.body.hostId === hostId)?.body ?? {
                    ...defaults,
                    hostId,
                  },
                );
              }}
            >
              <option value="">Tenant default</option>
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Name
            <input
              value={policy.name}
              required
              maxLength={100}
              onChange={(e) => set("name", e.target.value)}
            />
          </label>
          {(
            [
              ["intervalMinutes", "Backup interval (minutes)", 5, 10080],
              ["retentionDays", "Retention (days)", 1, 3650],
              ["sizeCapBytes", "Repository size cap (bytes)", 1, 1e12],
              ["massDeleteThreshold", "Mass delete threshold", 1, 1e6],
              [
                "missedBackupMinutes",
                "Missed backup threshold (minutes)",
                10,
                43200,
              ],
              [
                "restoreTestIntervalHours",
                "Restore test interval (hours)",
                1,
                8760,
              ],
            ] as const
          ).map(([key, label, min, max]) => (
            <label key={key}>
              {label}
              <input
                type="number"
                required
                min={min}
                max={max}
                value={policy[key]}
                onChange={(e) => set(key, e.target.valueAsNumber)}
              />
            </label>
          ))}
          <label>
            Storage
            <select
              value={policy.storage}
              onChange={(e) =>
                set("storage", e.target.value as Policy["storage"])
              }
            >
              {["local", "s3", "r2", "azure", "gdrive", "onedrive"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </label>
          <label>
            Residency requirement
            <select
              value={policy.residency}
              onChange={(e) =>
                set("residency", e.target.value as Policy["residency"])
              }
            >
              <option value="AU">Australia</option>
              <option value="unrestricted">Unrestricted</option>
            </select>
          </label>
          <label>
            Storage reference
            <input
              value={policy.storageRef}
              required
              onChange={(e) => set("storageRef", e.target.value)}
            />
          </label>
          <label>
            Key reference
            <input
              value={policy.keyRef}
              required
              onChange={(e) => set("keyRef", e.target.value)}
            />
          </label>
        </div>
        <label>
          Exclusions (one pattern per line)
          <textarea
            rows={5}
            value={policy.exclusions.join("\n")}
            onChange={(e) => set("exclusions", e.target.value.split("\n"))}
          />
        </label>
        {(
          [
            ["endOfSession", "Back up at the end of each session"],
            ["immutable", "Require immutable primary storage"],
            ["drCopy", "Require a second immutable disaster recovery copy"],
          ] as const
        ).map(([key, label]) => (
          <label className="check" key={key}>
            <input
              type="checkbox"
              checked={policy[key]}
              onChange={(e) => set(key, e.target.checked)}
            />
            {label}
          </label>
        ))}
        {!lockCapableStorage.includes(policy.storage) && (
          <p className="warning" role="note">
            {policy.storage} storage does not support object lock or
            immutability. Immutable primary storage and disaster recovery copies
            need s3 or azure.
          </p>
        )}
        {protectionError && (
          <p className="error" role="alert">
            {protectionError}
          </p>
        )}
        <p className="muted">
          These are requested policy requirements. Saving a policy does not
          validate storage capabilities or prove host enforcement. Alert
          delivery: UI only.
        </p>
        <Button disabled={!!protectionError}>Save policy</Button>
      </fieldset>
    </form>
  );
}
