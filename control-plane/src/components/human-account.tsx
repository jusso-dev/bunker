"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { components } from "../lib/api.generated";
import { api, apiPage } from "../lib/client";
import { Button } from "./ui/button";

type Session = components["schemas"]["sessionRow"];
export function AccountSettings({
  localPassword,
  clearSession,
  onError,
}: {
  localPassword: boolean;
  clearSession: () => void;
  onError: (error: unknown) => void;
}) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const version = useRef(0);
  const lifecycle = useRef(0);
  const refresh = useCallback(async () => {
    const current = ++version.current;
    const page = await apiPage<Session[]>("auth/sessions");
    if (version.current !== current) return;
    setSessions(page.data);
    setNext(page.next);
  }, []);
  useEffect(() => {
    let active = true;
    void refresh().catch((error) => {
      if (active) onError(error);
    });
    return () => {
      active = false;
      version.current += 1;
      lifecycle.current += 1;
    };
  }, [refresh, onError]);
  async function run(action: (active: () => boolean) => Promise<void>) {
    setBusy(true);
    setNotice("");
    const current = lifecycle.current;
    try {
      await action(() => lifecycle.current === current);
    } catch (error) {
      if (lifecycle.current === current) onError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      {notice && <p role="status">{notice}</p>}
      <section className="panel">
        <h2>Active sessions</h2>
        <p>
          Manage your own sessions across all tenants. Revocation takes effect
          immediately.
        </p>
        <Button
          disabled={busy}
          variant="outline"
          onClick={() =>
            void run(async (active) => {
              await api("auth/sessions/revoke-others", {});
              if (!active()) return;
              await refresh();
              setNotice("Other sessions revoked.");
            })
          }
        >
          Sign out other sessions
        </Button>
        {sessions.map((session) => (
          <div className="row" key={session.handle}>
            <div>
              <strong>
                {session.current ? "This session" : "Other session"}
              </strong>
              <small>
                Created {new Date(session.created_at).toLocaleString()} ·
                expires {new Date(session.expires_at).toLocaleString()}
              </small>
            </div>
            <Button
              disabled={busy}
              variant="outline"
              onClick={() =>
                void run(async (active) => {
                  await api(`auth/sessions/${session.handle}/revoke`, {});
                  if (!active()) return;
                  if (session.current) clearSession();
                  else {
                    await refresh();
                    setNotice("Session revoked.");
                  }
                })
              }
            >
              {session.current ? "Sign out this session" : "Revoke session"}
            </Button>
          </div>
        ))}
        {next && (
          <Button
            disabled={busy}
            variant="outline"
            onClick={() =>
              void run(async () => {
                const current = ++version.current;
                const page = await apiPage<Session[]>("auth/sessions", next);
                if (current !== version.current) return;
                setSessions((rows) => [
                  ...rows,
                  ...page.data.filter(
                    (item) => !rows.some((row) => row.handle === item.handle),
                  ),
                ]);
                setNext(page.next);
              })
            }
          >
            Load more sessions
          </Button>
        )}
      </section>
      <section className="panel">
        <h2>Change password</h2>
        {localPassword ? (
          <>
            <p>
              Enter your current local password. Changing it signs out every
              session, including this one. Linked provider identities stay
              linked.
            </p>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const form = event.currentTarget;
                const fields = new FormData(form);
                void run(async (active) => {
                  await api("auth/password", {
                    currentPassword: fields.get("currentPassword"),
                    newPassword: fields.get("newPassword"),
                  });
                  if (!active()) return;
                  form.reset();
                  clearSession();
                });
              }}
            >
              <label>
                Current password
                <input
                  name="currentPassword"
                  type="password"
                  required
                  maxLength={256}
                  autoComplete="current-password"
                />
              </label>
              <label>
                New password
                <input
                  name="newPassword"
                  type="password"
                  required
                  minLength={14}
                  maxLength={256}
                  autoComplete="new-password"
                />
              </label>
              <Button disabled={busy}>Change password and sign out</Button>
            </form>
          </>
        ) : (
          <p>
            Manage your credential with your identity provider. Local password
            recovery cannot create a local login.
          </p>
        )}
      </section>
    </>
  );
}

export function RecoveryForm({
  busy,
  run,
  done,
}: {
  busy: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  done: () => void;
}) {
  return (
    <details>
      <summary>Use an operator-issued recovery token</summary>
      <p>
        For an existing local account only. Ask your instance operator to verify
        your identity and issue a one-use token. It expires after 15 minutes; no
        email is sent. Use your provider for federated credentials.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const fields = new FormData(form);
          void run(async () => {
            await api("auth/recovery", {
              token: fields.get("token"),
              newPassword: fields.get("newPassword"),
            });
            form.reset();
            done();
          });
        }}
      >
        <label>
          Recovery token
          <input
            name="token"
            type="password"
            required
            minLength={43}
            maxLength={43}
            autoComplete="off"
          />
        </label>
        <label>
          New password
          <input
            name="newPassword"
            type="password"
            required
            minLength={14}
            maxLength={256}
            autoComplete="new-password"
          />
        </label>
        <Button disabled={busy}>Recover local password</Button>
      </form>
    </details>
  );
}
