import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join as joinPath } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import {
  resolveUserName,
  maskEnv,
  isSecretKey,
  isSecretValue,
} from "./config.js";
import { loadRelayConfigFile } from "../relay.js";
import { registryAdd, registryRemove, registryList } from "./registry.js";
import type {
  InstallOptions,
  LogOptions,
  ServiceConfig,
  ServiceInfo,
  ServiceInstallResult,
  ServiceManager,
  ServiceStatus,
} from "./types.js";

export function cliEntrypoint(): string {
  return fileURLToPath(new URL("../cli.js", import.meta.url));
}

export function nodeExecutable(): string {
  return process.execPath;
}

export function unitPathFor(name: string, opts: InstallOptions = {}): string {
  if (opts.user) {
    return joinPath(
      os.homedir(),
      ".config",
      "systemd",
      "user",
      `${name}.service`,
    );
  }
  return joinPath("/etc/systemd/system", `${name}.service`);
}

export function renderUnit(
  config: ServiceConfig,
  opts: InstallOptions = {},
): string {
  const user = resolveUserName(config.user);
  const userLine = opts.user ? "" : `User=${user}\n`;
  const envLines = Object.entries(config.env)
    .map(([key, value]) => `Environment=${key}=${value}`)
    .join("\n");
  const restart = config.restart;
  const restartSec = restart.onFailure
    ? `Restart=on-failure\nRestartSec=${restart.delaySeconds}s\nStartLimitBurst=${restart.maxRetries}`
    : "Restart=no";
  const execParts = [
    config.script ? config.script : cliEntrypoint(),
    ...config.args,
  ];
  const execStart = [nodeExecutable(), ...execParts].join(" ");
  return `[Unit]
Description=${config.description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${userLine}WorkingDirectory=${config.workingDir}
ExecStart=${execStart}
${restartSec}
${envLines ? `${envLines}\n` : ""}StandardOutput=journal
StandardError=journal
SyslogIdentifier=${config.name}

[Install]
WantedBy=${opts.user ? "default.target" : "multi-user.target"}
`;
}

function systemctl(
  args: string[],
  opts: { user?: boolean; tolerateFailure?: boolean } = {},
): string {
  const full = [...(opts.user ? ["--user"] : []), ...args];
  const result = spawnSync("systemctl", full, { encoding: "utf8" });
  if (result.status !== 0 && !opts.tolerateFailure) {
    const stderr = (result.stderr ?? "").trim();
    throw new Error(
      `SERVICE_SYSTEMCTL_FAILED: systemctl ${full.join(" ")} failed${
        stderr ? `: ${stderr}` : ""
      }`,
    );
  }
  return (result.stdout ?? "").trim();
}

function systemctlUser(scope: "system" | "user"): boolean {
  return scope === "user";
}

export class LinuxServiceManager implements ServiceManager {
  async install(
    config: ServiceConfig,
    opts: InstallOptions = {},
  ): Promise<ServiceInstallResult> {
    const scope = opts.user ? "user" : "system";
    const unitPath = unitPathFor(config.name, opts);
    if (existsSync(unitPath)) {
      throw new Error(
        `SERVICE_ALREADY_EXISTS: unit file already exists at ${unitPath}`,
      );
    }
    const unit = renderUnit(config, opts);
    mkdirSync(dirname(unitPath), { recursive: true });
    writeFileSync(unitPath, unit, "utf8");
    try {
      systemctl(["daemon-reload"], { user: scope === "user" });
      systemctl(["enable", "--now", config.name], {
        user: scope === "user",
      });
    } catch (error) {
      rmSync(unitPath, { force: true });
      throw error;
    }
    const status = await statusForScope(config.name, scope);
    let settled = status;
    if (status.status !== "running") {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await new Promise((r) => setTimeout(r, 500));
        try {
          settled = await statusForScope(config.name, scope);
        } catch {
          break;
        }
        if (settled.status === "running") break;
      }
    }
    const portsListening = detectRelayPorts(config.args);
    const info: ServiceInfo = {
      name: config.name,
      status: settled.status,
      pid: settled.pid,
      platform: "linux",
      scope,
      unitPath,
      installedAt: new Date().toISOString(),
    };
    await registryAdd(info);
    return {
      installed: true,
      name: config.name,
      platform: "linux",
      scope,
      unitPath,
      status: settled.status,
      pid: settled.pid,
      portsListening,
    };
  }

  async uninstall(name: string): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    if (!info) {
      throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not registered`);
    }
    const unitPath = info.unitPath;
    if (unitPath && existsSync(unitPath)) {
      systemctl(["disable", "--now", name], {
        user: systemctlUser(info.scope),
        tolerateFailure: true,
      });
      rmSync(unitPath, { force: true });
      systemctl(["daemon-reload"], {
        user: systemctlUser(info.scope),
        tolerateFailure: true,
      });
    }
    await registryRemove(name);
  }

  async start(name: string): Promise<void> {
    const scope = await scopeFor(name);
    systemctl(["start", name], { user: systemctlUser(scope) });
  }

  async stop(name: string): Promise<void> {
    const scope = await scopeFor(name);
    systemctl(["stop", name], { user: systemctlUser(scope) });
  }

  async restart(name: string): Promise<void> {
    const scope = await scopeFor(name);
    systemctl(["restart", name], { user: systemctlUser(scope) });
  }

  async status(name: string): Promise<ServiceStatus> {
    const scope = await scopeFor(name);
    return statusForScope(name, scope);
  }

  async logs(name: string, opts: LogOptions): Promise<void> {
    const scope = await scopeFor(name);
    const args = [
      ...(scope === "user" ? ["--user"] : []),
      "-u",
      name,
      "-n",
      String(opts.lines),
      "--no-pager",
      ...(opts.follow ? ["-f"] : []),
    ];
    await new Promise<void>((resolve, reject) => {
      const child = spawn("journalctl", args, { stdio: "inherit" });
      child.on("close", () => resolve());
      child.on("error", (error) => {
        reject(new Error(`SERVICE_JOURNALCTL_FAILED: ${error.message}`));
      });
    });
  }

  async list(): Promise<ServiceInfo[]> {
    const entries = registryList();
    return entries.map((info) => ({
      ...info,
      platform: "linux",
    }));
  }
}

async function scopeFor(name: string): Promise<"system" | "user"> {
  const info = registryList().find((e) => e.name === name);
  if (!info) {
    throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not installed`);
  }
  return info.scope;
}

export async function statusForScope(
  name: string,
  scope: "system" | "user",
): Promise<ServiceStatus> {
  const show = systemctl(
    [
      "show",
      name,
      "-p",
      "ActiveState",
      "-p",
      "SubState",
      "-p",
      "MainPID",
      "-p",
      "ExecMainStartTimestamp",
      "-p",
      "NRestarts",
    ],
    { user: scope === "user", tolerateFailure: true },
  );
  if (!show && !existsSync(unitPathFor(name, { user: scope === "user" }))) {
    throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not installed`);
  }
  const fields = new Map<string, string>();
  for (const line of show.split("\n")) {
    const idx = line.indexOf("=");
    if (idx === -1) continue;
    fields.set(line.slice(0, idx), line.slice(idx + 1));
  }
  const active = fields.get("ActiveState") ?? "unknown";
  const pidRaw = fields.get("MainPID") ?? "0";
  const pid = pidRaw && pidRaw !== "0" ? Number(pidRaw) : undefined;
  const startedRaw = fields.get("ExecMainStartTimestamp") ?? "";
  let uptimeSeconds: number | undefined;
  if (startedRaw) {
    const started = new Date(startedRaw);
    if (!Number.isNaN(started.getTime())) {
      uptimeSeconds = Math.max(
        0,
        Math.floor((Date.now() - started.getTime()) / 1000),
      );
    }
  }
  const restartCount = Number(fields.get("NRestarts") ?? 0);
  let status: ServiceStatus["status"];
  if (active === "active") {
    status = fields.get("SubState") === "failed" ? "error" : "running";
  } else if (active === "inactive" || active === "dead") {
    status = "stopped";
  } else if (active === "failed") {
    status = "error";
  } else {
    status = "unknown";
  }
  return { name, status, pid, uptimeSeconds, restartCount };
}

export function detectRelayPorts(args: string[]): number[] {
  const ports: number[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if ((arg === "--listen" || arg === "-l") && args[i + 1]) {
      const port = Number(args[i + 1]);
      if (Number.isFinite(port) && port > 0 && port <= 65535) ports.push(port);
    }
    if ((arg === "--map" || arg === "-m") && args[i + 1]) {
      for (const part of args[i + 1]!.split(/[\s,]+/)) {
        const bits = part.split(":");
        if (bits.length < 2) continue;
        const listenBit =
          bits.length >= 3 && bits[0] !== "0.0.0.0"
            ? bits[0]
            : bits.length === 2
              ? bits[0]
              : undefined;
        const candidate = listenBit ? Number(listenBit) : undefined;
        if (
          candidate !== undefined &&
          Number.isFinite(candidate) &&
          candidate > 0 &&
          candidate <= 65535
        ) {
          ports.push(candidate);
        }
      }
    }
    if ((arg === "--file" || arg === "-f") && args[i + 1]) {
      try {
        for (const m of loadRelayConfigFile(args[i + 1]!)) {
          if (m.listenPort > 0 && m.listenPort <= 65535) {
            ports.push(m.listenPort);
          }
        }
      } catch {
        // ignore unreadable relay config file
      }
    }
  }
  return [...new Set(ports)];
}

export function lingerEnabled(user: string): boolean {
  const show = spawnSync("loginctl", ["show-user", user, "-p", "Linger"], {
    encoding: "utf8",
  });
  return show.status === 0 && /Linger=yes/i.test(show.stdout ?? "");
}
export function listeningPortsLinux(): number[] {
  const ports: number[] = [];
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let raw: string;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n").slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 4 || fields[3] !== "0A") continue;
      const local = fields[1]!;
      const portHex = local.split(":").at(-1);
      if (!portHex) continue;
      const port = Number.parseInt(portHex, 16);
      if (Number.isFinite(port) && port > 0) ports.push(port);
    }
  }
  return [...new Set(ports)];
}

export function maskedEnvLog(config: ServiceConfig): Record<string, string> {
  return maskEnv(config.env);
}

export function hasSecretEnv(config: ServiceConfig): boolean {
  return Object.entries(config.env).some(
    ([key, value]) => isSecretKey(key) || isSecretValue(value),
  );
}
