import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { cacheBinDir, cacheBinaryVersion } from "./binary.js";
import { sleep } from "./utils.js";

const execFileAsync = promisify(execFile);

export interface DaemonState {
  running: boolean;
  warnings: string[];
  actions: string[];
}

async function tryRun(command: string, args: string[]): Promise<boolean> {
  try {
    await execFileAsync(command, args, { timeout: 20_000, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

async function trySystemctl(args: string[]): Promise<boolean> {
  try {
    const { stdout, stderr } = await execFileAsync("systemctl", args, {
      timeout: 20_000,
      windowsHide: true,
    });
    if (/["']?systemd["']?\s+is\s+not\s+running/i.test(`${stdout}\n${stderr}`))
      return false;
    return true;
  } catch {
    return false;
  }
}

export async function inspectDaemon(): Promise<DaemonState> {
  if (process.platform === "win32") {
    const serviceUp = await tryRun("sc", ["query", "Tailscale"]);
    if (serviceUp) return { running: true, warnings: [], actions: [] };
    return {
      running: false,
      warnings: [
        'DAEMON_WINDOWS: the Tailscale Windows service is not running; start it in an Administrator shell with "net start Tailscale"',
      ],
      actions: [],
    };
  }

  if (await trySystemctl(["is-active", "tailscaled"]))
    return { running: true, warnings: [], actions: [] };
  if (await tryRun("pgrep", ["-x", "tailscaled"]))
    return { running: true, warnings: [], actions: [] };
  if ((await userspacePids()).length > 0)
    return { running: true, warnings: [], actions: [] };

  const warnings: string[] = [];
  if (!existsSync("/dev/net/tun")) {
    warnings.push(
      "DAEMON_CLIENT: /dev/net/tun is missing, so TUN mode cannot work; a userspace-networking tailscaled is the fallback",
    );
  }
  warnings.push(
    'TAILSCALED_NOT_RUNNING: tailscaled is not running; start it with "sudo systemctl enable --now tailscaled" (or "sudo tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock" on containers/devcontainers)',
  );
  return { running: false, warnings, actions: [] };
}

async function cachedDaemonPath(): Promise<string | undefined> {
  const version = await cacheBinaryVersion();
  if (!version) return undefined;
  const path_ = join(cacheBinDir(), `tailscaled-${version}`);
  return existsSync(path_) ? path_ : undefined;
}

async function resolveDaemonBin(): Promise<string> {
  if (await tryRun("tailscaled", ["--version"])) return "tailscaled";
  return (await cachedDaemonPath()) ?? "tailscaled";
}

async function startUserspaceDaemon(stateDir?: string): Promise<{
  started: boolean;
  command: string;
}> {
  const bin = await resolveDaemonBin();
  const root = typeof process.getuid === "function" && process.getuid() === 0;
  const socket =
    process.env.TS_TAILSCALE_SOCKET?.trim() ||
    (root
      ? "/var/run/tailscale/tailscaled.sock"
      : join(cacheBinDir(), "run", "tailscaled.sock"));
  const state =
    process.env.TS_TAILSCALED_STATE?.trim() ||
    (stateDir
      ? join(stateDir, "tailscaled.state")
      : root
        ? "/var/lib/tailscale/tailscaled.state"
        : join(cacheBinDir(), "tailscaled.state"));
  const args = [
    "--tun=userspace-networking",
    `--state=${state}`,
    `--statedir=${dirname(state)}`,
    `--socket=${socket}`,
  ];
  for (const path_ of [dirname(state), dirname(socket)]) {
    try {
      mkdirSync(path_, { recursive: true });
    } catch {
      // best-effort; the daemon fails loudly when a dir cannot be created
    }
  }
  const command = [bin, ...args];
  const child = spawn(bin, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.on("error", () => {
    // The daemon may exit immediately when privileges are missing.
  });
  child.unref();
  for (let attempt = 0; attempt < 10; attempt += 1) {
    await sleep(500);
    const pids = await userspacePids();
    if (pids[0]) {
      writeTrackedDaemon({
        pid: pids[0],
        socket,
        command: command.join(" "),
        startedAt: new Date().toISOString(),
      });
      if (!process.env.TS_TAILSCALE_SOCKET)
        process.env.TS_TAILSCALE_SOCKET = socket;
      return { started: true, command: command.join(" ") };
    }
  }
  return { started: false, command: command.join(" ") };
}

export async function trackedUserspaceSocket(): Promise<string | undefined> {
  const tracked = readTrackedDaemon();
  if (!tracked?.socket) return undefined;
  if (!(isUserspaceTailscaled(tracked.pid) && (await isAlive(tracked.pid))))
    return undefined;
  return tracked.socket;
}

export async function ensureDaemon(options?: {
  stateDir?: string;
}): Promise<DaemonState> {
  const inspected = await inspectDaemon();
  if (inspected.running) {
    if (!process.env.TS_TAILSCALE_SOCKET) {
      const socket = await trackedUserspaceSocket();
      if (socket) process.env.TS_TAILSCALE_SOCKET = socket;
    }
    return inspected;
  }
  if (process.platform === "win32") return inspected;

  const actions: string[] = [];
  if (await trySystemctl(["enable", "--now", "tailscaled"])) {
    actions.push("sudo systemctl enable --now tailscaled");
    return { running: true, warnings: [], actions };
  }

  const userspace = await startUserspaceDaemon(options?.stateDir);
  if (userspace.started) {
    return {
      running: true,
      warnings: [
        `DAEMON_USERSPACE: started a userspace-networking tailscaled (socket ${process.env.TS_TAILSCALE_SOCKET ?? "/var/run/tailscale/tailscaled.sock"}); no /dev/net/tun is required`,
      ],
      actions: [userspace.command],
    };
  }
  return {
    running: false,
    warnings: [
      ...inspected.warnings,
      `DAEMON_USERSPACE_FAILED: could not start a userspace daemon (${userspace.command}); start it manually with the exact command above`,
    ],
    actions,
  };
}

export interface TrackedDaemon {
  pid: number;
  socket: string;
  command: string;
  startedAt: string;
}

function daemonPidFile(): string {
  return join(cacheBinDir(), "daemon.pid.json");
}

export function readTrackedDaemon(): TrackedDaemon | undefined {
  try {
    const parsed = JSON.parse(
      readFileSync(daemonPidFile(), "utf8"),
    ) as Partial<TrackedDaemon>;
    if (typeof parsed.pid !== "number" || !Number.isInteger(parsed.pid))
      return undefined;
    return {
      pid: parsed.pid,
      socket: String(parsed.socket ?? ""),
      command: String(parsed.command ?? ""),
      startedAt: String(parsed.startedAt ?? ""),
    };
  } catch {
    return undefined;
  }
}

function writeTrackedDaemon(record: TrackedDaemon): void {
  const file = daemonPidFile();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
}

function clearTrackedDaemon(pid: number): void {
  const current = readTrackedDaemon();
  if (current && current.pid === pid) {
    try {
      rmSync(daemonPidFile());
    } catch {
      // best-effort cleanup
    }
  }
}

function pidCmdline(pid: number): string | undefined {
  if (process.platform !== "linux") return undefined;
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").replace(/\0/g, " ");
  } catch {
    return undefined;
  }
}

function isUserspaceTailscaled(pid: number): boolean {
  const cmdline = pidCmdline(pid);
  if (cmdline !== undefined)
    return (
      cmdline.includes("tailscaled") && cmdline.includes("userspace-networking")
    );
  return false;
}

async function userspacePids(): Promise<number[]> {
  try {
    const { stdout } = await execFileAsync(
      "pgrep",
      ["-f", "tailscaled.*--tun=userspace-networking"],
      { timeout: 10_000, windowsHide: true },
    );
    return stdout
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((value) => Number(value))
      .filter(Number.isInteger);
  } catch {
    return [];
  }
}

async function isAlive(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function stopUserspaceDaemon(): Promise<{
  stopped: boolean;
  pid?: number;
  message: string;
}> {
  const tracked = readTrackedDaemon();
  if (!tracked)
    return {
      stopped: false,
      message:
        "NO_TRACKED_DAEMON: no userspace tailscaled started by this tool is tracked (tracked in the daemon pidfile)",
    };
  const { pid } = tracked;
  if (!isUserspaceTailscaled(pid)) {
    clearTrackedDaemon(pid);
    return {
      stopped: false,
      pid,
      message: `UNTRACKED_PID: pid ${pid} is not a userspace tailscaled anymore (${pidCmdline(pid) ?? "process gone"}); cleared the stale pidfile`,
    };
  }
  if (!(await isAlive(pid))) {
    clearTrackedDaemon(pid);
    return {
      stopped: false,
      pid,
      message: `ALREADY_STOPPED: pid ${pid} is not running; cleared the pidfile`,
    };
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch (error) {
    return {
      stopped: false,
      pid,
      message: `KILL_FAILED: could not signal pid ${pid} (${error instanceof Error ? error.message : String(error)})`,
    };
  }
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await sleep(500);
    if (!(await isAlive(pid))) {
      clearTrackedDaemon(pid);
      return {
        stopped: true,
        pid,
        message: `stopped userspace tailscaled (pid ${pid})`,
      };
    }
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // fall through to the alive check below
  }
  await sleep(500);
  if (!(await isAlive(pid))) {
    clearTrackedDaemon(pid);
    return {
      stopped: true,
      pid,
      message: `stopped userspace tailscaled (pid ${pid}, after SIGKILL)`,
    };
  }
  return {
    stopped: false,
    pid,
    message: `KILL_FAILED: pid ${pid} survived SIGTERM and SIGKILL`,
  };
}

export async function daemonStatus(): Promise<{
  running: boolean;
  warnings: string[];
  actions: string[];
  tracked?: TrackedDaemon;
  trackedAlive: boolean;
}> {
  const inspected = await inspectDaemon();
  const tracked = readTrackedDaemon();
  let trackedAlive = false;
  if (tracked)
    trackedAlive =
      isUserspaceTailscaled(tracked.pid) && (await isAlive(tracked.pid));
  const base = {
    running: inspected.running,
    warnings: inspected.warnings,
    actions: inspected.actions,
    trackedAlive,
  };
  return tracked ? { ...base, tracked } : base;
}
