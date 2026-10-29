import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Socket } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";

test(
  "worker bounds stalled PostgreSQL setup and exits after termination",
  { timeout: 20000 },
  async () => {
    const sockets = new Set<Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const worker = spawn(
      process.execPath,
      ["--import", "tsx", "scripts/notifications.ts"],
      {
        cwd: new URL("..", import.meta.url),
        env: {
          PATH: process.env.PATH,
          NODE_ENV: "test",
          DATABASE_URL: `postgres://fixture:fixture@127.0.0.1:${address.port}/fixture`,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "";
    worker.stdout.on("data", (data) => {
      output += data.toString();
    });
    worker.stderr.on("data", (data) => {
      output += data.toString();
    });
    const exit = once(worker, "exit");
    const emergency = setTimeout(() => worker.kill("SIGKILL"), 14000);
    try {
      await Promise.race([
        once(server, "connection"),
        exit.then(() => {
          throw new Error("worker exited before database connection");
        }),
      ]);
      const start = Date.now();
      worker.kill("SIGTERM");
      const [code, signal] = await exit;
      assert.equal(signal, null);
      assert.equal(code, 1);
      assert.ok(
        Date.now() - start < 12000,
        "database connection exceeded bounded deadline",
      );
      assert.match(output, /check database availability/);
      assert.ok(!output.includes("postgres://"));
    } finally {
      clearTimeout(emergency);
      if (worker.exitCode === null && worker.signalCode === null) {
        worker.kill("SIGKILL");
        await exit;
      }
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

function packet(type: string, body: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeInt32BE(body.length + 4);
  return Buffer.concat([Buffer.from(type), length, body]);
}
test(
  "idle PostgreSQL failures are handled without exposing server details",
  { timeout: 20000 },
  async () => {
    const marker = "SYNTHETIC_PRIVATE_DATABASE_DETAIL";
    const ready = () => packet("Z", Buffer.from("I"));
    const sockets = new Set<Socket>();
    let commits = 0;
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      socket.on("error", () => {});
      let buffer: Buffer = Buffer.alloc(0),
        startup = true;
      socket.on("data", (data) => {
        buffer = Buffer.concat([buffer, data]);
        for (;;) {
          if (startup) {
            if (buffer.length < 4) return;
            const length = buffer.readInt32BE(0);
            if (buffer.length < length) return;
            buffer = buffer.subarray(length);
            startup = false;
            socket.write(
              Buffer.concat([packet("R", Buffer.alloc(4)), ready()]),
            );
            continue;
          }
          if (buffer.length < 5) return;
          const length = buffer.readInt32BE(1);
          if (buffer.length < length + 1) return;
          const type = String.fromCharCode(buffer[0]),
            body = buffer.subarray(5, length + 1);
          buffer = buffer.subarray(length + 1);
          if (type === "Q") {
            const sql = body.toString();
            socket.write(
              Buffer.concat([
                packet(
                  "C",
                  Buffer.from(
                    sql.startsWith("COMMIT")
                      ? "COMMIT\0"
                      : sql.startsWith("BEGIN")
                        ? "BEGIN\0"
                        : "UPDATE 0\0",
                  ),
                ),
                ready(),
              ]),
            );
            if (sql.startsWith("COMMIT")) {
              commits++;
              setTimeout(() => {
                if (!socket.destroyed)
                  socket.write(
                    packet(
                      "E",
                      Buffer.from(`SFATAL\0C57P01\0M${marker}\0D${marker}\0\0`),
                    ),
                  );
              }, 100).unref();
            }
          } else if (type === "P") socket.write(packet("1", Buffer.alloc(0)));
          else if (type === "B") socket.write(packet("2", Buffer.alloc(0)));
          else if (type === "D") socket.write(packet("n", Buffer.alloc(0)));
          else if (type === "E")
            socket.write(packet("C", Buffer.from("UPDATE 0\0")));
          else if (type === "S") socket.write(ready());
          else if (type === "X") socket.end();
        }
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const worker = spawn(
      process.execPath,
      ["--import", "tsx", "scripts/notifications.ts"],
      {
        cwd: new URL("..", import.meta.url),
        env: {
          PATH: process.env.PATH,
          NODE_ENV: "test",
          DATABASE_URL: `postgres://fixture:fixture@127.0.0.1:${address.port}/fixture`,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const exit = once(worker, "exit");
    let output = "",
      stopped = false;
    for (const stream of [worker.stdout, worker.stderr])
      stream.on("data", (data) => {
        output += data.toString();
        if (
          !stopped &&
          output.includes("Database idle connection failed; reconnecting.")
        ) {
          stopped = true;
          worker.kill("SIGTERM");
        }
      });
    const emergency = setTimeout(() => worker.kill("SIGKILL"), 12000);
    try {
      const [code, signal] = await exit;
      assert.equal(signal, null);
      assert.equal(code, 0);
      assert.ok(commits > 0);
      assert.ok(stopped);
      assert.ok(!output.includes(marker));
      assert.ok(!output.includes("Unhandled 'error'"));
    } finally {
      clearTimeout(emergency);
      if (worker.exitCode === null && worker.signalCode === null) {
        worker.kill("SIGKILL");
        await exit;
      }
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);
