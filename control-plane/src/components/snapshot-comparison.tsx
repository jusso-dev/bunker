export type ComparisonSnapshot = {
  id: string;
  body: { fileCount: number; totalBytes: number; manifestDigest: string };
};

// Keep selected metadata independently of the rolling latest-200 timeline.
// Missing selections are also safe during a tenant/session reset.
export function SnapshotComparison({
  snapshots,
  onClear,
}: {
  snapshots: readonly (ComparisonSnapshot | undefined)[];
  onClear?: () => void;
}) {
  const rows = snapshots.filter((row): row is ComparisonSnapshot => !!row);
  if (rows.length !== 2) return null;
  return (
    <section className="panel">
      <h2>Snapshot metadata comparison</h2>
      {rows.map((s) => (
        <p key={s.id}>
          <code>{s.id}</code>
          <br />
          {s.body.fileCount} files · {s.body.totalBytes.toLocaleString()} bytes
          · manifest <code>{s.body.manifestDigest}</code>
        </p>
      ))}
      <p>
        File contents and decrypted diff stay on the host. Run the local daemon
        diff for these snapshots before requesting restore.
      </p>
      <button onClick={onClear}>Clear comparison</button>
    </section>
  );
}
