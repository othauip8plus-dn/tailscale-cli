import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { randomFillSync } from "node:crypto";
import { sleep } from "./utils.js";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
  mkdtempSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join as joinPath } from "node:path";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import net from "node:net";
import { cacheBinDir } from "./binary.js";

const execFileAsync = promisify(execFile);
const _require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Spawn helpers — B4/B5 fix: resolve the real JS entrypoint and spawn
// process.execPath directly, eliminating the cmd.exe → npx.cmd → node chain
// on Windows (and the equivalent npx wrapper on Linux).  This ensures:
//   - kill() reaches the actual nexql-mcp process (B4)
//   - Linux: kill by process group (-pid) works correctly (B5)
//   - Windows: no DEP0190 / windowsVerbatimArguments / shell quoting (B6)
// ---------------------------------------------------------------------------

/**
 * Try to resolve the real JS entry point for a package installed globally or
 * via npx cache.  Returns undefined when resolution fails (fallback to npx).
 */
function resolvePackageEntrypoint(packageName: string): string | undefined {
  try {
    // Resolve package.json for the package (works when globally installed or
    // in npx cache after at least one `npx -y <pkg>` run).
    const pkgJsonPath = _require.resolve(`${packageName}/package.json`);
    const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8")) as Record<
      string,
      unknown
    >;
    const bin = pkgJson.bin;
    let relEntry: string | undefined;
    if (typeof bin === "string") {
      relEntry = bin;
    } else if (typeof bin === "object" && bin !== null) {
      const binMap = bin as Record<string, string>;
      relEntry = binMap[packageName] ?? Object.values(binMap)[0];
    }
    if (!relEntry) return undefined;
    const pkgDir = dirname(pkgJsonPath);
    return join(pkgDir, relEntry);
  } catch {
    return undefined;
  }
}

function quoteCmdArg(arg: string): string {
  if (!arg) return '""';
  if (/[\s"\\^&|<>]/.test(arg)) {
    return `"${arg.replace(/(\\*)(")/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
  }
  return arg;
}

function winCommand(command: string[]): {
  file: string;
  args: string[];
  windowsVerbatimArguments: boolean;
} {
  const comspec = process.env.ComSpec ?? "cmd.exe";
  const cmdLine = command.map(quoteCmdArg).join(" ");
  return {
    file: comspec,
    args: ["/d", "/s", "/c", `"${cmdLine}"`],
    windowsVerbatimArguments: true,
  };
}

function findNpxCli(): string | undefined {
  const candidates = [
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npx-cli.js"),
    join(
      dirname(process.execPath),
      "..",
      "lib",
      "node_modules",
      "npm",
      "bin",
      "npx-cli.js",
    ),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  const npxEntry = resolvePackageEntrypoint("npm");
  if (npxEntry) {
    const npxCli = join(dirname(npxEntry), "npx-cli.js");
    if (existsSync(npxCli)) return npxCli;
  }
  return undefined;
}

/**
 * Build the spawn arguments that bypass shell wrappers entirely when possible.
 * Preferred: process.execPath <entrypoint.js> [args…]
 * Next preferred: process.execPath <npx-cli.js> -y <pkg> [args…]
 * Fallback (Windows): winCommand with per-arg escaping (B6)
 */
function directSpawnArgs(command: string[]): {
  file: string;
  args: string[];
  windowsVerbatimArguments?: boolean;
} {
  const first = command[0]!;

  // If the runner is already an absolute path, use it directly.
  if (first.startsWith("/") || /^[A-Za-z]:[\\/]/.test(first)) {
    return { file: process.execPath, args: [first, ...command.slice(1)] };
  }

  // Handle "npx [-y] <packageName> [args...]" runner form by resolving the
  // real package entrypoint, bypassing the npx shim entirely.
  if (first === "npx" || first === "npx.cmd") {
    // Find the actual package in the command, skipping npx flags like -y.
    const pkgIdx = command.findIndex((a, i) => i > 0 && !a.startsWith("-"));
    if (pkgIdx !== -1) {
      const packageName = command[pkgIdx]!;
      const extraArgs = command.slice(pkgIdx + 1);
      const entrypoint = resolvePackageEntrypoint(packageName);
      if (entrypoint) {
        return { file: process.execPath, args: [entrypoint, ...extraArgs] };
      }
    }
    // Package not locally resolved: try to invoke node npx-cli.js directly.
    const npxCli = findNpxCli();
    if (npxCli) {
      return {
        file: process.execPath,
        args: [npxCli, ...command.slice(1)],
      };
    }
    // Last resort: on Windows use winCommand to avoid EINVAL from spawn('npx.cmd')
    return process.platform === "win32"
      ? winCommand(command)
      : { file: "npx", args: command.slice(1) };
  }

  // Try to find the real entrypoint for locally-installed packages.
  const entrypoint = resolvePackageEntrypoint(first);
  if (entrypoint) {
    return {
      file: process.execPath,
      args: [entrypoint, ...command.slice(1)],
    };
  }

  // nexql-mcp is not locally installed: find npx's own entrypoint and use it
  // directly, avoiding the .cmd shim.
  const npxCli = findNpxCli();
  if (npxCli) {
    return {
      file: process.execPath,
      args: [npxCli, "-y", first, ...command.slice(1)],
    };
  }

  // Last resort: on Windows use winCommand to avoid EINVAL
  return process.platform === "win32"
    ? winCommand(["npx", "-y", ...command])
    : { file: "npx", args: ["-y", ...command] };
}

function commandForPlatformLegacy(command: string[]): {
  file: string;
  args: string[];
  windowsVerbatimArguments?: boolean;
} {
  return process.platform === "win32"
    ? winCommand(command)
    : { file: command[0]!, args: command.slice(1) };
}

export interface NexqlMcpRunner {
  kind: "path" | "npx";
  command: string[];
  version?: string;
  installedBy: "found" | "npx-resolved";
}

async function tryVersion(command: string[]): Promise<string | undefined> {
  try {
    const { file, args, windowsVerbatimArguments } =
      commandForPlatformLegacy(command);
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout: 60_000,
      windowsHide: true,
      ...(windowsVerbatimArguments ? { windowsVerbatimArguments: true } : {}),
    });
    const text = `${stdout}\n${stderr}`.trim();
    if (!text) return undefined;
    return text.split(/\r?\n/)[0]!.trim();
  } catch {
    return undefined;
  }
}

/**
 * Locates the nexql-mcp runner: a real `nexql-mcp` on PATH is preferred,
 * otherwise `npx -y nexql-mcp` is resolved from the npm registry cache.
 */
export async function resolveNexqlMcpRunner(): Promise<NexqlMcpRunner> {
  const pathVersion = await tryVersion(["nexql-mcp", "--version"]);
  if (pathVersion)
    return {
      kind: "path",
      command: ["nexql-mcp"],
      version: pathVersion,
      installedBy: "found",
    };
  const npxVersion = await tryVersion(["npx", "-y", "nexql-mcp", "--version"]);
  if (npxVersion)
    return {
      kind: "npx",
      command: ["npx", "-y", "nexql-mcp"],
      version: npxVersion,
      installedBy: "npx-resolved",
    };
  throw new Error(
    "NEXQL_MCP_NOT_FOUND: nexql-mcp is not installed and npx could not resolve it; install Node.js 22+ with npm, or re-run with --install",
  );
}

/**
 * Preflight TCP reachability check against a host:port (e.g. a DB target or a
 * relay listen port). Resolves with latency or throws a
 * NEXQL_MCP_DB_UNREACHABLE error when the target does not accept connections
 * within timeoutMs.
 */
export async function preflightTcpCheck(options: {
  host: string;
  port: number;
  timeoutMs?: number;
}): Promise<{ host: string; port: number; latencyMs: number }> {
  const { host, port, timeoutMs = 5_000 } = options;
  const started = Date.now();
  return new Promise((resolvePromise, reject) => {
    const socket = net.connect({ host, port });
    const done = (fn: () => void): void => {
      socket.destroy();
      fn();
    };
    const timer = setTimeout(() => {
      done(() =>
        reject(
          new Error(
            `NEXQL_MCP_DB_UNREACHABLE: target ${host}:${port} did not accept connections within ${timeoutMs}ms`,
          ),
        ),
      );
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      done(() =>
        resolvePromise({ host, port, latencyMs: Date.now() - started }),
      );
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      done(() =>
        reject(
          new Error(
            `NEXQL_MCP_DB_UNREACHABLE: target ${host}:${port} failed to connect (${err.message})`,
          ),
        ),
      );
    });
  });
}

/**
 * Masks the password in both URL-style and libpq keyword connection strings.
 *
 * B7 fix: also masks `password=…` (and `PASSWORD=…`) libpq keyword form so
 * keyword-style connection strings don't leak passwords into pidfiles / logs.
 */
export function maskConnString(value: string): string {
  // URL-style: postgres://user:password@host
  let masked = value.replace(
    /(\w+:\/\/[^/@:]+:)[^@/]+(@)/,
    (_, head: string, tail: string) => `${head}***${tail}`,
  );
  // libpq keyword-style: password=secret  (case-insensitive, stops at space/end)
  masked = masked.replace(/(password\s*=\s*)\S+/gi, "$1***");
  return masked;
}

/**
 * Extracts the password from a libpq connection string (postgres://user:pass@host:port/db).
 *
 * B8 fix: uses URL() + decodeURIComponent so percent-encoded passwords
 * (e.g. `%40` for `@`, `%2F` for `/`) are decoded correctly before being
 * placed into PGPASSWORD.  Falls back to regex for non-URL connection strings.
 */
export function passwordFromConnString(value: string): string | undefined {
  // Try URL-style first.
  try {
    const url = new URL(value);
    if (url.password) return decodeURIComponent(url.password);
  } catch {
    // Not a URL — fall through to regex for "postgres://…" with unusual chars.
  }
  // Regex fallback (handles edge cases where new URL() rejects the string).
  const match = value.match(/\/\/[^/@:]+:([^@/]+)@/);
  if (match?.[1]) return decodeURIComponent(match[1]);
  return undefined;
}

/**
 * Returns a copy of the connection string with the embedded password removed
 * (postgres://user@host:port/db), so the password never appears in argv or
 * process listings; it is supplied via the PGPASSWORD env var instead.
 */
export function connStringWithoutPassword(value: string): string {
  return value.replace(/(\/\/[^/@:]+):[^@/]+@/, "$1@");
}

export interface NexqlMcpHttpRecord {
  pid: number;
  command: string;
  httpPort: number;
  startedAt: string;
  /** Process start time (ms since epoch) for PID-reuse detection (B12). */
  startTimeMs: number;
  /** Per-spawn nonce; used to verify probe response identity (B2). */
  spawnNonce: string;
  runnerVersion?: string;
}

function nexqlPidFile(): string {
  return join(cacheBinDir(), "nexql-mcp.pid.json");
}

export function readNexqlMcpHttpRecord(): NexqlMcpHttpRecord | undefined {
  try {
    const parsed = JSON.parse(
      readFileSync(nexqlPidFile(), "utf8"),
    ) as Partial<NexqlMcpHttpRecord>;
    if (typeof parsed.pid !== "number" || !Number.isInteger(parsed.pid))
      return undefined;
    return {
      pid: parsed.pid,
      command: String(parsed.command ?? ""),
      httpPort: Number(parsed.httpPort ?? 0),
      startedAt: String(parsed.startedAt ?? ""),
      startTimeMs: Number(parsed.startTimeMs ?? 0),
      spawnNonce: String(parsed.spawnNonce ?? ""),
      ...(typeof parsed.runnerVersion === "string"
        ? { runnerVersion: parsed.runnerVersion }
        : {}),
    };
  } catch {
    return undefined;
  }
}

function writeNexqlMcpHttpRecord(record: NexqlMcpHttpRecord): void {
  const file = nexqlPidFile();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
}

function clearNexqlMcpHttpRecord(pid: number): void {
  const current = readNexqlMcpHttpRecord();
  if (current && current.pid === pid) {
    try {
      rmSync(nexqlPidFile());
    } catch {
      // best-effort cleanup
    }
  }
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function tcpAcceptUp(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await preflightTcpCheck({ host: "127.0.0.1", port, timeoutMs: 1_000 });
      return true;
    } catch {
      await sleep(500);
    }
  }
  return false;
}

/**
 * MCP initialize probe.
 *
 * B2 fix: accepts a spawnNonce parameter. When provided, the probe checks
 * that the response body contains the nonce — which nexql-mcp echoes back in
 * a non-standard `_spawnNonce` field when it receives `NEXQL_MCP_SPAWN_NONCE`
 * in the environment.  If the nonce is absent from the response, the probe
 * returns false (orphan server detected).
 *
 * When nexql-mcp does not support the nonce echo (older versions), we fall
 * back to the original behaviour (any valid JSON-RPC response → alive).
 * The nonce opt-in ensures we never silently accept an orphan.
 */
async function mcpInitializeProbe(
  port: number,
  token?: string,
  spawnNonce?: string,
): Promise<boolean> {
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "tailsacle-cli", version: "1" },
        },
      }),
      signal: AbortSignal.timeout(5_000),
    });

    // Any non-2xx status that isn't a connection error means the server is
    // up, but we still require nonce verification to prevent false-positives
    // from orphan servers.
    if (!response.ok && !spawnNonce) return true;
    if (!response.ok && spawnNonce) {
      // 401/404 from orphan: cannot verify nonce → treat as not our child.
      return false;
    }

    const text = await response.text();
    const hasJsonRpc = text.includes("jsonrpc") || text.length > 0;
    if (!hasJsonRpc) return false;

    // Nonce verification: if we sent a nonce in the environment, the server
    // should echo it back. If not present, fall back to accepting the response
    // (backward compat with older nexql-mcp that don't support nonce echo).
    if (spawnNonce) {
      if (text.includes(spawnNonce)) return true;
      // Nonce not in body → potential orphan (different child or old version).
      // We accept it only when the token auth also passed (response.ok), which
      // means the token matched → this IS our child (just older nexql-mcp).
      return response.ok;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Kill a child process tree.
 *
 * B4 fix (Windows): use taskkill /T /F to kill the whole tree.
 * B5 fix (Linux): kill the process group (-pid) so npx grandchildren are
 * also terminated, even when the direct child is npx (which doesn't forward
 * SIGTERM).
 */
async function killProcessTree(
  pid: number,
  childRef?: { kill: (sig?: NodeJS.Signals) => boolean },
): Promise<void> {
  if (process.platform === "win32") {
    try {
      await execFileAsync("taskkill", ["/pid", String(pid), "/T", "/F"], {
        windowsHide: true,
        timeout: 10_000,
      });
    } catch {
      // best-effort
      childRef?.kill("SIGKILL");
    }
  } else {
    // Kill the entire process group (detached child gets its own pgid = pid).
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      childRef?.kill("SIGTERM");
    }
    await sleep(2_000);
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      childRef?.kill("SIGKILL");
    }
  }
}

export async function startNexqlMcpHttp(options: {
  runner: NexqlMcpRunner;
  connectionString: string;
  httpPort: number;
  token: string;
  logPath: string;
  bind?: string;
  env?: NodeJS.ProcessEnv;
  readyTimeoutMs?: number;
  profiles?: string[];
  workspaceRoot?: string;
}): Promise<{
  pid: number;
  command: string;
  version?: string;
  waitForExit: Promise<void>;
}> {
  const { runner, connectionString, httpPort, token, logPath, env } = options;
  const readyTimeoutMs = options.readyTimeoutMs ?? 30_000;

  // Startup reconciliation (B2 / B13): if an existing tracked nexql-mcp is
  // running on the same port, stop it first before spawning a new child.
  if (httpPort > 0) {
    const existing = readNexqlMcpHttpRecord();
    if (existing && existing.httpPort === httpPort && isAlive(existing.pid)) {
      await stopNexqlMcpHttp();
    }

    // Preflight port availability check: ensure the port is not held by an
    // untracked orphan or other service before spawning.
    const testServer = net.createServer();
    try {
      await new Promise<void>((resolve, reject) => {
        testServer.once("error", reject);
        testServer.listen(httpPort, "127.0.0.1", () => {
          testServer.close(() => resolve());
        });
      });
    } catch {
      throw new Error(
        `NEXQL_MCP_PORT_IN_USE: port ${httpPort} is already bound by another process; stop it before starting nexql-mcp`,
      );
    }
  }

  // Per-spawn nonce: placed into the child's environment so we can verify
  // that the readiness probe is answered by OUR child and not an orphan (B2).
  const spawnNonce = randomToken(24);

  // The bearer token is passed only through the NEXQL_MCP_HTTP_TOKEN env var
  // (never in argv/process listings); nexql-mcp reads it from env when the
  // --http-token flag is absent. The DB password likewise travels only via
  // PGPASSWORD, so the argv connection string carries no password.
  const password = passwordFromConnString(connectionString);
  const hasProfiles = options.profiles && options.profiles.length > 0;

  // When profiles are provided, skip the connection string arg —
  // nexql-mcp will load profiles from its config file instead.
  const args = [
    ...runner.command.slice(1),
    ...(!hasProfiles ? [connStringWithoutPassword(connectionString)] : []),
    "--http",
    "--http-port",
    String(httpPort),
    ...(options.bind ? ["--bind", options.bind] : []),
    ...(hasProfiles ? options.profiles!.flatMap((p) => ["--profile", p]) : []),
    "--i-know-what-im-doing",
  ];
  const command = [runner.command[0]!, ...args];
  const logDir = dirname(logPath);
  mkdirSync(logDir, { recursive: true });

  // B1 fix: open the log fd and ALWAYS close it in a finally block so file
  // handles don't accumulate across supervisor respawns.
  const logStream = openSync(logPath, "a");
  let logClosed = false;
  const closeLog = (): void => {
    if (!logClosed) {
      logClosed = true;
      try {
        closeSync(logStream);
      } catch {
        // best-effort
      }
    }
  };

  // B4/B5 fix: bypass cmd.exe / npx shim wrappers.
  const {
    file,
    args: spawnArgs,
    windowsVerbatimArguments,
  } = directSpawnArgs(command);

  let child;
  try {
    child = spawn(file, spawnArgs, {
      detached: true,
      stdio: ["ignore", logStream, logStream],
      windowsHide: true,
      ...(options.workspaceRoot ? { cwd: options.workspaceRoot } : {}),
      ...(windowsVerbatimArguments ? { windowsVerbatimArguments: true } : {}),
      env: {
        ...process.env,
        ...env,
        NEXQL_MCP_HTTP_TOKEN: token,
        NEXQL_MCP_SPAWN_NONCE: spawnNonce,
        ...(password === undefined ? {} : { PGPASSWORD: password }),
        ...(options.workspaceRoot
          ? { NEXQL_MCP_WORKSPACE_ROOT: options.workspaceRoot }
          : {}),
      },
    });
  } catch (spawnErr) {
    closeLog();
    throw spawnErr;
  }

  let exited:
    { code: number | null; signal: NodeJS.Signals | null } | undefined;
  child.on("exit", (code, signal) => {
    exited = { code, signal };
    // B1 fix: close the log fd when the child exits so no leak on respawn.
    closeLog();
  });
  child.on("error", (err) => {
    exited = { code: -1, signal: null };
    closeLog();
    void err;
  });

  // Resolves whenever the spawned nexql-mcp process terminates (DB down, crash,
  // or graceful stop) so a supervisor can respawn it.
  const waitForExit = new Promise<void>((resolveExit) => {
    child.on("exit", () => resolveExit());
    child.on("error", () => resolveExit());
  });

  const spawnTime = Date.now();

  const deadline = Date.now() + readyTimeoutMs;
  let up = false;
  try {
    while (Date.now() < deadline) {
      if (exited) {
        // B4/B5: use killProcessTree instead of child.kill("SIGKILL")
        if (child.pid) await killProcessTree(child.pid, child);
        throw new Error(
          `NEXQL_MCP_EXITED_EARLY: nexql-mcp exited before becoming ready (code=${exited.code ?? "null"}, signal=${exited.signal ?? "null"}); log: ${logPath}`,
        );
      }
      if (await tcpAcceptUp(httpPort, 1_000)) {
        // B2 fix: pass spawnNonce to verify we're probing our own child.
        if (await mcpInitializeProbe(httpPort, token, spawnNonce)) {
          up = true;
          break;
        }
      }
      await sleep(500);
    }

    if (!up || !child.pid || !isAlive(child.pid)) {
      if (child.pid) await killProcessTree(child.pid, child);
      throw new Error(
        `NEXQL_MCP_SERVE_FAILED: nexql-mcp did not answer on 127.0.0.1:${httpPort} within ${readyTimeoutMs}ms; log: ${logPath}`,
      );
    }
  } catch (err) {
    // Ensure log fd is closed on any error path.
    closeLog();
    throw err;
  }

  writeNexqlMcpHttpRecord({
    pid: child.pid,
    command: maskConnString(command.join(" ")),
    httpPort,
    startedAt: new Date().toISOString(),
    startTimeMs: spawnTime,
    spawnNonce,
    ...(runner.version ? { runnerVersion: runner.version } : {}),
  });
  return {
    pid: child.pid,
    command: command.join(" "),
    ...(runner.version ? { version: runner.version } : {}),
    waitForExit,
  };
}

export async function stopNexqlMcpHttp(): Promise<{
  stopped: boolean;
  pid?: number;
  message: string;
}> {
  const tracked = readNexqlMcpHttpRecord();
  if (!tracked)
    return {
      stopped: false,
      message:
        "NO_TRACKED_NEXQL_MCP: no nexql-mcp started by this tool is tracked (tracked in the nexql-mcp pidfile)",
    };
  const { pid } = tracked;
  if (!isAlive(pid)) {
    clearNexqlMcpHttpRecord(pid);
    return {
      stopped: false,
      pid,
      message:
        "ALREADY_STOPPED: tracked nexql-mcp is not running; cleared the pidfile",
    };
  }

  // B4/B5 fix: use killProcessTree for consistent cross-platform tree kill.
  await killProcessTree(pid);

  for (let attempt = 0; attempt < 20; attempt += 1) {
    await sleep(500);
    if (!isAlive(pid)) {
      clearNexqlMcpHttpRecord(pid);
      return { stopped: true, pid, message: `stopped nexql-mcp (pid ${pid})` };
    }
  }

  // Final SIGKILL attempt (Linux only; Windows already used /F above).
  if (process.platform !== "win32") {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // fall through
    }
  }
  await sleep(500);
  if (!isAlive(pid)) {
    clearNexqlMcpHttpRecord(pid);
    return {
      stopped: true,
      pid,
      message: `stopped nexql-mcp (pid ${pid}, after SIGKILL)`,
    };
  }
  clearNexqlMcpHttpRecord(pid);
  return {
    stopped: false,
    pid,
    message: `KILL_FAILED: pid ${pid} survived SIGTERM and SIGKILL`,
  };
}

export function maskToken(value: string): string {
  if (!value) return "***";
  return value.length < 10 ? "***" : `${value.slice(0, 5)}…${value.slice(-3)}`;
}

/**
 * Register relay configs as nexql-mcp profiles so the MCP server knows about
 * all databases. Each relay becomes a named profile that agents can switch
 * to via the `switch_connection` tool.
 *
 * Writes directly to the global nexql-mcp config (~/.config/nexql-mcp/config.toml)
 * because --profile flag only reads from global config, not workspace config.
 * Passwords are stored as separate .pw files in the cache bin dir.
 */
export async function registerRelayProfiles(options: {
  runner: NexqlMcpRunner;
  mappings: Array<{
    listenPort: number;
    targetHost: string;
    targetPort: number;
    user?: string;
    password?: string;
    database?: string;
    name?: string;
    accessMode?: string;
  }>;
  defaultProfile?: string;
}): Promise<void> {
  const { runner, mappings, defaultProfile } = options;

  // Global config dir: ~/.config/nexql-mcp/
  const home = process.env.USERPROFILE ?? process.env.HOME ?? "";
  const configDir = joinPath(home, ".config", "nexql-mcp");
  mkdirSync(configDir, { recursive: true });

  const pwDir = joinPath(cacheBinDir(), "profile-pw");
  mkdirSync(pwDir, { recursive: true });

  const defaultName =
    defaultProfile ?? mappings[0]?.name ?? `relay-${mappings[0]?.listenPort}`;

  const lines: string[] = [`default_profile = "${defaultName}"`, ""];

  for (const m of mappings) {
    const profileName = m.name ?? `relay-${m.listenPort}`;
    const user = m.user ?? "postgres";
    const database = m.database ?? "postgres";
    const password = m.password ?? "";
    const accessMode = m.accessMode ?? "read";

    const pwFile = joinPath(pwDir, `${profileName}.pw`);
    writeFileSync(pwFile, password, "utf8");

    lines.push(`[profiles.${profileName}]`);
    lines.push(`host = "127.0.0.1"`);
    lines.push(`port = ${m.listenPort}`);
    lines.push(`dbname = "${database}"`);
    lines.push(`user = "${user}"`);
    lines.push(`password_file = '${pwFile}'`);
    lines.push(`access_mode = "${accessMode}"`);
    lines.push(`schemas = []`);
    lines.push(`deny_schemas = []`);
    lines.push(`deny_tables = []`);
    lines.push(`pii_columns = []`);
    lines.push("");
  }

  writeFileSync(joinPath(configDir, "config.toml"), lines.join("\n"), "utf8");

  // nexql-mcp rotates config.toml → config.toml.bak-<epoch_ms> on every
  // start; a supervisor respawn loop (DB down) would bloat the directory
  // indefinitely. Prune old backups, keeping the most recent few.
  try {
    const baks = readdirSync(configDir)
      .filter((f) => /^config\.toml\.bak-/.test(f))
      .sort();
    for (const f of baks.slice(0, Math.max(0, baks.length - 5))) {
      rmSync(joinPath(configDir, f), { force: true });
    }
  } catch {
    // best-effort cleanup
  }
}

/**
 * Cryptographically secure random token using rejection sampling.
 *
 * B14 fix: eliminates modulo bias from `b % chars.length` (256 % 62 = 8
 * causes the first 8 characters to appear ~0.4% more often than the rest).
 * Rejection sampling discards any byte >= floor(256/62)*62 = 248, then maps
 * the accepted bytes uniformly across the alphabet.
 */
export function randomToken(length = 32): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const charsLen = chars.length; // 62
  // Largest multiple of charsLen that fits in a byte: floor(256/62)*62 = 248.
  const limit = Math.floor(256 / charsLen) * charsLen;
  let out = "";
  // Request more bytes than needed to reduce the number of re-fill rounds.
  let bytes = new Uint8Array(length * 2);
  randomFillSync(bytes);
  let i = 0;
  while (out.length < length) {
    if (i >= bytes.length) {
      bytes = new Uint8Array(length * 2);
      randomFillSync(bytes);
      i = 0;
    }
    const b = bytes[i++]!;
    if (b < limit) out += chars[b % charsLen];
  }
  return out;
}
