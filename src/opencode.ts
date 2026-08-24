import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { cacheBinDir } from "./binary.js";
import { stopUserspaceDaemon } from "./daemon.js";
import {
  deploy,
  ensureFunnelReadiness,
  ensureSshReadiness,
  resolveTags,
  runFunnelWithAttrRetry,
} from "./deploy.js";
import { ensureHttpsEnabled } from "./policy.js";
import { TailscaleLocal, findTailscale } from "./tailscale.js";
import { verifyEndpointReachable } from "./verify.js";
import type { Exposure, ResolvedConfig } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * Windows npm shims (opencode.cmd, npx.cmd) can only be launched through a
 * shell; execFile/spawn reject .cmd files without one.
 */
function shellForWin32(): { shell?: boolean } {
  return process.platform === "win32" ? { shell: true } : {};
}

export const OPENCODE_PERMISSION_CONFIG = `{
  "$schema": "https://opencode.ai/config.json",
  "permission": "allow"
}
`;

export const DEFAULT_OPENCODE_PORT = 3000;

export interface OpenCodeRunner {
  kind: "path" | "npx";
  command: string[];
  version?: string;
  installedBy: "found" | "npx-resolved";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export async function tryVersion(
  command: string[],
): Promise<string | undefined> {
  try {
    const { stdout, stderr } = await execFileAsync(
      command[0]!,
      command.slice(1),
      {
        timeout: 60_000,
        windowsHide: true,
        ...shellForWin32(),
      },
    );
    const text = `${stdout}\n${stderr}`.trim();
    if (!text) return undefined;
    return text.split(/\r?\n/)[0]!.trim();
  } catch {
    return undefined;
  }
}

/**
 * Locates the opencode runner: a real `opencode` on PATH is preferred, otherwise
 * `npx -y opencode-ai` is resolved (which installs/uses the npm cache — this is
 * the "install opencode when missing" step, and `--install` forces it).
 */
export async function resolveOpenCodeRunner(
  options: {
    install?: boolean;
  } = {},
): Promise<OpenCodeRunner> {
  if (!options.install) {
    const pathVersion = await tryVersion(["opencode", "--version"]);
    if (pathVersion)
      return {
        kind: "path",
        command: ["opencode"],
        version: pathVersion,
        installedBy: "found",
      };
  }
  const npxVersion = await tryVersion([
    "npx",
    "-y",
    "opencode-ai",
    "--version",
  ]);
  if (npxVersion)
    return {
      kind: "npx",
      command: ["npx", "-y", "opencode-ai"],
      version: npxVersion,
      installedBy: "npx-resolved",
    };
  throw new Error(
    "OPENCODE_NOT_FOUND: opencode is not installed and npx could not resolve opencode-ai; install Node.js 22+ with npm, or re-run with --install",
  );
}

/**
 * `permission: "allow"` is the headless equivalent of `opencode --auto`
 * (serve has no --auto flag): every tool runs without approval — nothing is
 * blocked, exactly like auto mode. Explicit deny rules elsewhere still apply.
 */
export function writePermissionConfig(target?: string): {
  written: string[];
  existing: string[];
} {
  const written: string[] = [];
  const existing: string[] = [];
  const write = (file: string): void => {
    if (existsSync(file)) {
      existing.push(file);
      return;
    }
    try {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, OPENCODE_PERMISSION_CONFIG, "utf8");
      written.push(file);
    } catch {
      // best-effort: a missing permission file still falls back to OPENCODE_PERMISSION
    }
  };
  if (target) {
    write(resolve(target));
    return { written, existing };
  }
  const home = homedir();
  if (home) write(join(home, ".config", "opencode", "opencode.json"));
  write(resolve("opencode.json"));
  return { written, existing };
}

export interface OpenCodeServeRecord {
  pid: number;
  command: string;
  port: number;
  startedAt: string;
  runnerVersion?: string;
}

function openCodePidFile(): string {
  return join(cacheBinDir(), "opencode.pid.json");
}

export function readOpenCodeServeRecord(): OpenCodeServeRecord | undefined {
  try {
    const parsed = JSON.parse(
      readFileSync(openCodePidFile(), "utf8"),
    ) as Partial<OpenCodeServeRecord>;
    if (typeof parsed.pid !== "number" || !Number.isInteger(parsed.pid))
      return undefined;
    return {
      pid: parsed.pid,
      command: String(parsed.command ?? ""),
      port: Number(parsed.port ?? 0),
      startedAt: String(parsed.startedAt ?? ""),
      ...(typeof parsed.runnerVersion === "string"
        ? { runnerVersion: parsed.runnerVersion }
        : {}),
    };
  } catch {
    return undefined;
  }
}

function writeOpenCodeServeRecord(record: OpenCodeServeRecord): void {
  const file = openCodePidFile();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
}

function clearOpenCodeServeRecord(pid: number): void {
  const current = readOpenCodeServeRecord();
  if (current && current.pid === pid) {
    try {
      rmSync(openCodePidFile());
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

export async function serveHttpUp(
  port: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`, {
        signal: AbortSignal.timeout(2000),
      });
      void response;
      return true;
    } catch {
      await sleep(1000);
    }
  }
  return false;
}

export function openCodeServeArgs(
  runner: OpenCodeRunner,
  port: number,
): string[] {
  return [
    ...runner.command.slice(1),
    "serve",
    "--port",
    String(port),
    "--hostname",
    "127.0.0.1",
  ];
}

export async function startOpenCodeServe(options: {
  runner: OpenCodeRunner;
  port: number;
  configPath?: string;
  logPath: string;
}): Promise<{ pid: number; command: string }> {
  const args = openCodeServeArgs(options.runner, options.port);
  const command = [...options.runner.command, ...args];
  const logDir = dirname(options.logPath);
  mkdirSync(logDir, { recursive: true });
  const logStream = openSync(options.logPath, "a");
  const child = spawn(options.runner.command[0]!, args, {
    detached: true,
    stdio: ["ignore", logStream, logStream],
    windowsHide: true,
    ...shellForWin32(),
    env: {
      ...process.env,
      OPENCODE_DISABLE_AUTOUPDATE: "1",
      OPENCODE_PERMISSION: '{"*":"allow"}',
      ...(options.configPath
        ? { OPENCODE_CONFIG: resolve(options.configPath) }
        : {}),
    },
  });
  child.on("error", () => {
    // The server may exit immediately when the runner cannot start.
  });
  child.unref();
  const up = await serveHttpUp(options.port, 90_000);
  if (!up || !child.pid || !isAlive(child.pid)) {
    throw new Error(
      `OPENCODE_SERVE_FAILED: opencode serve did not answer on 127.0.0.1:${options.port} within 90s; log: ${options.logPath}`,
    );
  }
  writeOpenCodeServeRecord({
    pid: child.pid,
    command: command.join(" "),
    port: options.port,
    startedAt: new Date().toISOString(),
    ...(options.runner.version
      ? { runnerVersion: options.runner.version }
      : {}),
  });
  return { pid: child.pid, command: command.join(" ") };
}

export async function findOpenCodeServePids(port?: number): Promise<number[]> {
  try {
    const { stdout } = await execFileAsync("pgrep", ["-f", "opencode.*serve"], {
      timeout: 10_000,
      windowsHide: true,
    });
    const pids = stdout
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((value) => Number(value))
      .filter(Number.isInteger);
    if (!port) return pids;
    const matches: number[] = [];
    for (const pid of pids) {
      try {
        const args = readFileSync(`/proc/${pid}/cmdline`, "utf8").replace(
          /\0/g,
          " ",
        );
        if (args.includes(`--port ${port}`)) matches.push(pid);
      } catch {
        // process gone between pgrep and /proc read
      }
    }
    return matches;
  } catch {
    return [];
  }
}

export async function stopOpenCodeServe(): Promise<{
  stopped: boolean;
  pid?: number;
  message: string;
}> {
  const tracked = readOpenCodeServeRecord();
  if (!tracked)
    return {
      stopped: false,
      message:
        "NO_TRACKED_SERVE: no opencode serve started by this tool is tracked (tracked in the opencode pidfile)",
    };
  const { pid, port } = tracked;
  if (!isAlive(pid)) {
    clearOpenCodeServeRecord(pid);
    return {
      stopped: false,
      pid,
      message:
        "ALREADY_STOPPED: tracked opencode serve is not running; cleared the pidfile",
    };
  }
  if (process.platform === "win32") {
    // The tracked pid is the shell/cmd wrapper when the runner is a .cmd
    // shim; taskkill /T kills the whole process tree (serve + wrapper).
    try {
      await execFileAsync("taskkill", ["/pid", String(pid), "/T", "/F"], {
        windowsHide: true,
        timeout: 20_000,
      });
    } catch {
      // fall through to the alive check below
    }
  } else {
    try {
      process.kill(pid, "SIGTERM");
    } catch (error) {
      return {
        stopped: false,
        pid,
        message: `KILL_FAILED: could not signal pid ${pid} (${error instanceof Error ? error.message : String(error)})`,
      };
    }
  }
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await sleep(500);
    if (!isAlive(pid)) {
      clearOpenCodeServeRecord(pid);
      return {
        stopped: true,
        pid,
        message: `stopped opencode serve (pid ${pid})`,
      };
    }
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // fall through to the alive check below
  }
  await sleep(500);
  if (!isAlive(pid)) {
    clearOpenCodeServeRecord(pid);
    return {
      stopped: true,
      pid,
      message: `stopped opencode serve (pid ${pid}, after SIGKILL)`,
    };
  }
  const orphans = await findOpenCodeServePids(port);
  for (const orphan of orphans) {
    if (orphan === pid) continue;
    try {
      process.kill(orphan, "SIGKILL");
    } catch {
      // best-effort cleanup of npx-spawned children
    }
  }
  clearOpenCodeServeRecord(pid);
  return {
    stopped: true,
    pid,
    message: `KILL_FAILED: pid ${pid} survived SIGTERM and SIGKILL; signalled ${orphans.length} orphaned serve process(es)`,
  };
}

/** Public FQDN of the funnel node: `tailscale funnel status` name, else the Self DNSName. */
export async function funnelDnsName(
  local: TailscaleLocal,
): Promise<string | undefined> {
  try {
    const statusJson = await local.runJson<{ Name?: string }>([
      "funnel",
      "status",
    ]);
    if (typeof statusJson?.Name === "string")
      return statusJson.Name.replace(/\.$/, "");
  } catch {
    // status unavailable; fall back to local status.
  }
  try {
    const statusJson = await local.runJson<{ Self?: { DNSName?: string } }>([
      "status",
    ]);
    const dns = statusJson?.Self?.DNSName;
    return dns ? dns.replace(/\.$/, "") : undefined;
  } catch {
    return undefined;
  }
}

export function deriveUrls(
  dnsName: string | undefined,
  exposures: Exposure[],
  fallbackPort: number,
): string[] {
  if (!dnsName) return [];
  const urls = new Set<string>();
  for (const exposure of exposures) {
    const path = exposure.path
      ? exposure.path.startsWith("/")
        ? exposure.path
        : `/${exposure.path}`
      : "/";
    if (exposure.public) urls.add(`https://${dnsName}${path}`);
  }
  if (urls.size === 0) urls.add(`https://${dnsName}:${fallbackPort}`);
  return [...urls];
}

export interface OpenCodeFlowOptions {
  config: ResolvedConfig;
  port: number;
  yes: boolean;
  dryRun: boolean;
  install: boolean;
  verify: boolean;
  verifyTimeout: number;
  opencodeConfigPath?: string;
  applyPolicy?: boolean;
  enableHttps?: boolean;
  credentialEnvName?: string;
  tagOwner?: string[];
  backupDir?: string;
  logPath?: string;
}

export interface OpenCodeFlowResult {
  opencode: {
    runner: OpenCodeRunner;
    pid?: number;
    command?: string;
    port: number;
    configPath?: string;
    permissionConfig: string;
    permissionWritten: string[];
    permissionExisting: string[];
    logPath: string;
  };
  deployment: Awaited<ReturnType<typeof deploy>>;
  dnsName?: string;
  urls: string[];
  verified: boolean;
  verifyAttempts?: number;
}

export async function runOpenCodeFlow(
  options: OpenCodeFlowOptions,
): Promise<OpenCodeFlowResult> {
  const logPath = options.logPath ?? join(cacheBinDir(), "opencode-serve.log");
  const runner = await resolveOpenCodeRunner({ install: options.install });
  const permission = writePermissionConfig(options.opencodeConfigPath);
  const base = {
    runner,
    port: options.port,
    permissionConfig: OPENCODE_PERMISSION_CONFIG,
    permissionWritten: permission.written,
    permissionExisting: permission.existing,
    logPath,
    ...(options.opencodeConfigPath
      ? { configPath: options.opencodeConfigPath }
      : {}),
  };
  if (options.dryRun) {
    const deployment = await deploy(options.config, {
      dryRun: true,
      yes: options.yes,
      expose: [],
      funnel: false,
      ...(options.applyPolicy ? { applyPolicy: true } : {}),
      ...(options.credentialEnvName
        ? { credentialEnvName: options.credentialEnvName }
        : {}),
      ...(options.tagOwner?.length ? { tagOwner: options.tagOwner } : {}),
      ...(options.backupDir ? { backupDir: options.backupDir } : {}),
    });
    deployment.exposures = [
      {
        target: `http://127.0.0.1:${options.port}`,
        public: true,
        https: 443,
      },
    ];
    return { opencode: { ...base }, deployment, urls: [], verified: false };
  }

  const served = await startOpenCodeServe({
    runner,
    port: options.port,
    logPath,
    ...(options.opencodeConfigPath
      ? { configPath: options.opencodeConfigPath }
      : {}),
  });
  try {
    const deployment = await deploy(options.config, {
      dryRun: false,
      yes: options.yes,
      expose: [],
      funnel: false,
      ...(options.applyPolicy ? { applyPolicy: true } : {}),
      ...(options.credentialEnvName
        ? { credentialEnvName: options.credentialEnvName }
        : {}),
      ...(options.tagOwner?.length ? { tagOwner: options.tagOwner } : {}),
      ...(options.backupDir ? { backupDir: options.backupDir } : {}),
    });
    const warnings = [];
    const binary = await findTailscale();
    const local = new TailscaleLocal(binary);
    if (options.enableHttps) {
      warnings.push(
        ...(
          await ensureHttpsEnabled(options.config, {
            yes: true,
            ...(options.credentialEnvName
              ? { credentialEnvName: options.credentialEnvName }
              : {}),
          })
        ).warnings,
      );
    }
    const deploymentTags = resolveTags(options.config).tags;
    warnings.push(
      ...(await ensureFunnelReadiness(options.config, deploymentTags, {
        yes: options.yes,
        ...(options.applyPolicy ? { applyPolicy: true } : {}),
        ...(options.credentialEnvName
          ? { credentialEnvName: options.credentialEnvName }
          : {}),
        ...(options.backupDir ? { backupDir: options.backupDir } : {}),
      })),
    );
    if (options.config.ssh) {
      warnings.push(
        ...(await ensureSshReadiness(options.config, deploymentTags, {
          yes: options.yes,
          ...(options.applyPolicy ? { applyPolicy: true } : {}),
          ...(options.credentialEnvName
            ? { credentialEnvName: options.credentialEnvName }
            : {}),
          ...(options.backupDir ? { backupDir: options.backupDir } : {}),
        })),
      );
    }
    const target = `http://127.0.0.1:${options.port}`;
    await runFunnelWithAttrRetry(() =>
      local.funnel(["--bg", "--yes", "--https=443", target]),
    );
    deployment.exposures = [{ target, public: true, https: 443 }];
    const dnsName = await funnelDnsName(local);
    const urls = deriveUrls(dnsName, deployment.exposures, 443);
    let verified = false;
    let verifyAttempts: number | undefined;
    if (options.verify && dnsName) {
      const endpoint = await verifyEndpointReachable(
        dnsName,
        [443],
        "tls",
        options.verifyTimeout,
      );
      verifyAttempts = endpoint.attempts;
      if (!endpoint.ok) {
        throw new Error(
          `FUNNEL_ENDPOINT_UNREACHABLE: public DNS resolved for ${dnsName} but TLS/HTTPS was not reachable within ${options.verifyTimeout}s (tried ${endpoint.attempts} times${endpoint.lastError ? `; last error: ${endpoint.lastError}` : ""})`,
        );
      }
      verified = true;
    }
    return {
      opencode: {
        ...base,
        pid: served.pid,
        command: served.command,
      },
      deployment,
      ...(dnsName ? { dnsName } : {}),
      urls,
      verified,
      ...(verifyAttempts !== undefined ? { verifyAttempts } : {}),
      ...(warnings.length ? { warnings } : {}),
    };
  } catch (error) {
    const stop = await stopOpenCodeServe();
    if (error instanceof Error)
      throw new Error(`${error.message} (serve stopped: ${stop.message})`, {
        cause: error,
      });
    throw error;
  }
}

export async function stopOpenCodeFlow(): Promise<{
  serve: { stopped: boolean; pid?: number; message: string };
  daemon: { stopped: boolean; pid?: number; message: string };
}> {
  const serve = await stopOpenCodeServe();
  const daemon = await stopUserspaceDaemon();
  return { serve, daemon };
}
