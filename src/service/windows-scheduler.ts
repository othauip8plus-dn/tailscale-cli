import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  watchFile,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { registryAdd, registryRemove, registryList } from "./registry.js";
import { cliEntrypoint, nodeExecutable } from "./linux.js";
import type {
  InstallOptions,
  LogOptions,
  ServiceConfig,
  ServiceInfo,
  ServiceInstallResult,
  ServiceManager,
  ServiceStatus,
} from "./types.js";

const TASK_PREFIX = "tailsacle-cli\\";

export function taskPathFor(name: string): string {
  return `${TASK_PREFIX}${name}`;
}

function schtasks(args: string[], tolerateFailure = false): string {
  const result = spawnSync("schtasks", args, { encoding: "utf8" });
  if (result.status !== 0 && !tolerateFailure) {
    const stderr = (result.stderr ?? "").trim();
    throw new Error(
      `SERVICE_SCHTASKS_FAILED: schtasks ${args.join(" ")} failed${
        stderr ? `: ${stderr}` : ""
      }`,
    );
  }
  return (result.stdout ?? "").trim();
}

export function schedulerLogDir(name: string): string {
  const home =
    process.env.USERPROFILE ?? process.env.HOME ?? "C:\\Users\\Default";
  return `${home}\\.tailsacle-cli\\logs\\${name}`;
}

export function schedulerBatchPath(name: string, logDir: string): string {
  return `${logDir}\\run-${name}.cmd`;
}

function taskCommand(config: ServiceConfig, logDir: string): string {
  mkdirSync(logDir, { recursive: true });
  const batchPath = schedulerBatchPath(config.name, logDir);
  const execArgs = config.script
    ? [config.script, ...config.args]
    : [cliEntrypoint(), ...config.args];
  // (removed: outLog/errLog are now computed as safeOutLog/safeErrLog below)

  // B11 fix: escape literal % in all arguments so cmd.exe does not expand
  // them as environment-variable references (e.g. a token containing %FOO%
  // would otherwise be silently replaced by the value of %FOO%).
  const escapeBatchArg = (s: string): string => `"${s.replace(/%/g, "%%")}"`;
  const innerArgs = execArgs.map(escapeBatchArg).join(" ");
  // Also escape % in logDir / workingDir paths (rare but possible).
  const safeLogDir = logDir.replace(/%/g, "%%");
  const safeWorkingDir = config.workingDir.replace(/%/g, "%%");
  const safeOutLog = `${safeLogDir}\\out.log`;
  const safeErrLog = `${safeLogDir}\\err.log`;
  const content = `@echo off\r\nif not exist "${safeLogDir}" mkdir "${safeLogDir}"\r\ncd /d "${safeWorkingDir}"\r\n"${nodeExecutable()}" ${innerArgs} >>"${safeOutLog}" 2>>"${safeErrLog}"\r\n`;
  writeFileSync(batchPath, content, "utf8");
  return `cmd /c "${batchPath}"`;
}

function taskExists(name: string): boolean {
  const result = spawnSync("schtasks", ["/query", "/tn", taskPathFor(name)], {
    encoding: "utf8",
  });
  return result.status === 0;
}

export class WindowsSchedulerManager implements ServiceManager {
  async install(
    config: ServiceConfig,
    _opts: InstallOptions = {},
  ): Promise<ServiceInstallResult> {
    if (taskExists(config.name)) {
      throw new Error(
        `SERVICE_ALREADY_EXISTS: scheduled task "${taskPathFor(config.name)}" already exists`,
      );
    }
    const logDir = config.log?.dir ?? schedulerLogDir(config.name);
    const args = [
      "/create",
      "/tn",
      taskPathFor(config.name),
      "/tr",
      taskCommand(config, logDir),
      "/sc",
      "onlogon",
      "/f",
    ];
    schtasks(args);
    const info: ServiceInfo = {
      name: config.name,
      status: "unknown",
      platform: "win32",
      scope: "user",
      unitPath: taskPathFor(config.name),
      logDir,
      installedAt: new Date().toISOString(),
    };
    await registryAdd(info);
    return {
      installed: true,
      name: config.name,
      platform: "win32",
      scope: "user",
      unitPath: taskPathFor(config.name),
      status: "unknown",
    };
  }

  async uninstall(name: string): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    if (!info) {
      throw new Error(`SERVICE_NOT_FOUND: service "${name}" is not registered`);
    }
    schtasks(["/end", "/tn", taskPathFor(name)], true);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      schtasks(["/delete", "/tn", taskPathFor(name), "/f"], true);
      if (!taskExists(name)) break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    if (taskExists(name)) {
      throw new Error(
        `SERVICE_SCHTASKS_FAILED: could not delete scheduled task "${taskPathFor(name)}"`,
      );
    }
    if (info.logDir) {
      try {
        const batchPath = schedulerBatchPath(name, info.logDir);
        if (existsSync(batchPath)) rmSync(batchPath, { force: true });
      } catch {
        // best effort
      }
    }
    await registryRemove(name);
  }

  async start(name: string): Promise<void> {
    schtasks(["/run", "/tn", taskPathFor(name)]);
  }

  async stop(name: string): Promise<void> {
    schtasks(["/end", "/tn", taskPathFor(name)], true);
  }

  async restart(name: string): Promise<void> {
    await this.stop(name);
    await this.start(name);
  }

  async status(name: string): Promise<ServiceStatus> {
    const result = spawnSync(
      "schtasks",
      ["/query", "/tn", taskPathFor(name), "/fo", "LIST", "/v"],
      { encoding: "utf8" },
    );
    if (result.status !== 0) {
      throw new Error(
        `SERVICE_NOT_FOUND: task "${taskPathFor(name)}" not found`,
      );
    }
    const output = result.stdout ?? "";
    const statusMatch = /Status:\s*(.+)/.exec(output);
    const raw = statusMatch?.[1]?.trim() ?? "";
    let status: ServiceStatus["status"];
    if (raw.startsWith("Running")) status = "running";
    else if (raw.startsWith("Ready") || raw.startsWith("Disabled")) {
      status = "stopped";
    } else if (raw && raw !== "Unknown") status = "error";
    else status = "unknown";
    return { name, status };
  }

  async logs(name: string, opts: LogOptions): Promise<void> {
    const info = registryList().find((e) => e.name === name);
    const logDir = info?.logDir ?? schedulerLogDir(name);
    const outFile = `${logDir}\\out.log`;
    const errFile = `${logDir}\\err.log`;

    const tail = (filePath: string, label: string): void => {
      if (!existsSync(filePath)) {
        console.log(
          `[tailsacle-service] ${label}: no log file yet: ${filePath}`,
        );
        return;
      }
      const content = readFileSync(filePath, "utf8");
      const lines = content.split("\n").slice(-Math.max(1, opts.lines));
      console.log(lines.join("\n"));
    };

    tail(outFile, "stdout");
    tail(errFile, "stderr");

    if (opts.follow) {
      await new Promise<void>((resolve) => {
        const watch = (filePath: string, label: string): void => {
          if (!existsSync(filePath)) return;
          watchFile(filePath, { interval: 1000 }, () => {
            tail(filePath, label);
          });
        };
        watch(outFile, "stdout");
        watch(errFile, "stderr");
        process.once("SIGINT", () => resolve());
        process.once("SIGTERM", () => resolve());
      });
    }
  }

  async list(): Promise<ServiceInfo[]> {
    return registryList().map((info) => ({
      ...info,
      platform: "win32",
    }));
  }
}
