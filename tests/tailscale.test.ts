import { describe, expect, it } from "vitest";
import { chmod, mkdtemp, writeFile, rename } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TailscaleLocal } from "../src/tailscale.js";
import { cacheBinDir } from "../src/binary.js";

async function fakeTailscaleBin(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "tscli-shim-"));
  const shim = join(dir, "tailscale");
  await writeFile(shim, "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\"\n");
  await chmod(shim, 0o755);
  return shim;
}

// The POSIX shell shim cannot be spawned on Windows (execFile rejects .cmd
// wrappers with EINVAL and there is no portable script executable); the
// --socket pass-through logic is platform-independent and covered by the
// Linux matrix jobs.
const skipOnWindows = process.platform === "win32";

describe("TailscaleLocal --socket pass-through", () => {
  it.skipIf(skipOnWindows)(
    "prefixes --socket from options.env when set",
    async () => {
      const shim = await fakeTailscaleBin();
      const local = new TailscaleLocal(shim);
      const result = await local.run(["status"], {
        env: { TS_TAILSCALE_SOCKET: "/tmp/env-sock/tailscaled.sock" },
      });
      expect(result.stdout.split("\n")[0]).toBe(
        "--socket=/tmp/env-sock/tailscaled.sock",
      );
      expect(result.stdout.split("\n")[1]).toBe("status");
    },
  );

  it.skipIf(skipOnWindows)(
    "falls back to process.env.TS_TAILSCALE_SOCKET when options.env is absent",
    async () => {
      const previous = process.env.TS_TAILSCALE_SOCKET;
      process.env.TS_TAILSCALE_SOCKET = "/tmp/shared-sock/tailscaled.sock";
      try {
        const shim = await fakeTailscaleBin();
        const result = await new TailscaleLocal(shim).run(["status"]);
        expect(result.stdout.split("\n")[0]).toBe(
          "--socket=/tmp/shared-sock/tailscaled.sock",
        );
      } finally {
        if (previous === undefined) delete process.env.TS_TAILSCALE_SOCKET;
        else process.env.TS_TAILSCALE_SOCKET = previous;
      }
    },
  );

  it.skipIf(skipOnWindows)(
    "passes args through unchanged when no socket is configured",
    async () => {
      const previous = process.env.TS_TAILSCALE_SOCKET;
      if (previous !== undefined) delete process.env.TS_TAILSCALE_SOCKET;
      // Temporarily hide the tracked daemon pidfile so trackedUserspaceSocket()
      // does not inject a socket path from a prior daemon start.
      const pidFile = join(cacheBinDir(), "daemon.pid.json");
      const hiddenPidFile = `${pidFile}.test-hidden`;
      const hadPidFile = existsSync(pidFile);
      if (hadPidFile) await rename(pidFile, hiddenPidFile);
      try {
        const shim = await fakeTailscaleBin();
        const result = await new TailscaleLocal(shim).run(["status"]);
        expect(result.stdout.split("\n")[0]).toBe("status");
      } finally {
        if (hadPidFile) await rename(hiddenPidFile, pidFile);
        if (previous !== undefined) process.env.TS_TAILSCALE_SOCKET = previous;
      }
    },
  );
});
