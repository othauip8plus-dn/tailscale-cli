#!/usr/bin/env node

import { Command } from "commander";
import { loadConfigFile, resolveConfig } from "./core.js";
import {
  DEFAULT_OPENCODE_PORT,
  runOpenCodeFlow,
  stopOpenCodeFlow,
} from "./opencode.js";
import type { Envelope } from "./types.js";
import { packageVersion } from "./utils.js";

const DOCS_BASE =
  "https://github.com/ongtrieuphuchieu689-7u/tailscale-cli/blob/main/docs";

const program = new Command();
program
  .name("tailscale-cli-opencode")
  .description(
    "Install (via npx) and serve opencode with full permissions, then publish it publicly through a Tailscale Funnel",
  )
  .version(packageVersion())
  .option("--json", "emit a stable JSON envelope")
  .option("--port <number>", "local port for opencode serve (default: 3000)")
  .option("--yes", "skip confirmation prompts")
  .option("--install", "force resolution via npx -y opencode-ai")
  .option(
    "--opencode-config <path>",
    "path to the opencode.json permission file to create/use (default: ~/.config/opencode/opencode.json and ./opencode.json)",
  )
  .option("--no-verify", "skip the public DNS + live TLS endpoint verification")
  .option(
    "--verify-timeout <seconds>",
    "public DNS and live-endpoint verification timeout (default: 120)",
  )
  .option("--dry-run", "plan only: no install, no serve, no deploy")
  .option("--stop", "stop the tracked opencode serve and userspace tailscaled")
  .option(
    "--apply-policy",
    "allow HuJSON-preserving tagOwners/nodeAttrs provisioning",
  )
  .option("--enable-https", "enable tailnet-wide HTTPS (required for Funnel)")
  .option("--state-dir <path>", "state directory for tailscaled")
  .option("--backup-dir <path>", "directory for policy backups")
  .option("--tag-owner <owner...>", "owner(s) for auto-provisioned tagOwners")
  .option(
    "--credential-env <name>",
    "use the Tailscale trust credential found in this env var",
  )
  .option("--profile <profile>", "override the active Tailscale profile")
  .option("--config <path>", "path to tailscale-cli.config.json");

function tailscaleEnv(): NodeJS.ProcessEnv {
  const opts = program.opts<Record<string, unknown>>();
  let env = process.env;
  const loaded = loadConfigFile(
    typeof opts.config === "string" ? opts.config : undefined,
  );
  if (loaded) {
    const fileEnv = { ...env };
    const { config } = loaded;
    if (config.profile && !env.TS_PROFILE) fileEnv.TS_PROFILE = config.profile;
    if (config.tailnet && !env.TS_TAILNET) fileEnv.TS_TAILNET = config.tailnet;
    if (config.hostname && !env.TS_HOSTNAME)
      fileEnv.TS_HOSTNAME = config.hostname;
    if (config.tags?.length && !env.TS_TAGS)
      fileEnv.TS_TAGS = config.tags.join(",");
    if (config.credentialEnv && !env.TS_CREDENTIAL_ENV)
      fileEnv.TS_CREDENTIAL_ENV = config.credentialEnv;
    if (config.tagOwner?.length && !env.TS_TAG_OWNER)
      fileEnv.TS_TAG_OWNER = config.tagOwner.join(",");
    env = fileEnv;
  }
  if (typeof opts.profile === "string")
    env = { ...env, TS_PROFILE: opts.profile };
  return env;
}

function emit<T>(
  command: string,
  resolved: T,
  warnings: string[] = [],
  sideEffects: string[] = [],
  requiredPrivileges: string[] = [],
  start = performance.now(),
): void {
  const envelope: Envelope<T> = {
    ok: true,
    command,
    resolved,
    durationMs: Math.round(performance.now() - start),
    warnings,
    requiredPrivileges,
    sideEffects,
    retryable: false,
  };
  if (program.opts<{ json?: boolean }>().json)
    console.log(JSON.stringify(envelope, null, 2));
  else console.log(JSON.stringify(resolved, null, 2));
}

function fail(
  command: string,
  error: unknown,
  start = performance.now(),
): never {
  const message = error instanceof Error ? error.message : String(error);
  const code = message.split(":")[0]!.trim();
  const funnelCodes = [
    "FUNNEL_PORT_UNSUPPORTED",
    "FUNNEL_ATTR_REQUIRED",
    "FUNNEL_DNS_NOT_PUBLISHED",
    "FUNNEL_ENDPOINT_UNREACHABLE",
    "OPENCODE_SERVE_FAILED",
  ];
  const docsUrl = funnelCodes.includes(code)
    ? `${DOCS_BASE}/user_requirement.md#funnel`
    : code === "OPENCODE_NOT_FOUND"
      ? `${DOCS_BASE}/user_requirement.md#opencode`
      : undefined;
  const envelope: Envelope<never> = {
    ok: false,
    command,
    durationMs: Math.round(performance.now() - start),
    warnings: [],
    requiredPrivileges: [],
    sideEffects: [],
    retryable: false,
    error: {
      code,
      message,
      ...(docsUrl ? { docsUrl } : {}),
    },
  };
  if (program.opts<{ json?: boolean }>().json)
    console.error(JSON.stringify(envelope, null, 2));
  else console.error(`ERROR ${code}: ${message}`);
  process.exitCode = funnelCodes.includes(code) ? 7 : 1;
  return undefined as never;
}

program.action(
  async (options: {
    json?: boolean;
    port?: string;
    yes?: boolean;
    install?: boolean;
    opencodeConfig?: string;
    verify?: boolean;
    verifyTimeout?: string;
    dryRun?: boolean;
    stop?: boolean;
    applyPolicy?: boolean;
    enableHttps?: boolean;
    stateDir?: string;
    backupDir?: string;
    tagOwner?: string[];
    credentialEnv?: string;
    profile?: string;
    config?: string;
  }) => {
    const start = performance.now();
    if (options.stop) {
      try {
        const result = await stopOpenCodeFlow();
        emit(
          "opencode",
          result,
          [],
          ["stop opencode serve", "stop tracked userspace tailscaled"],
          [],
          start,
        );
        return;
      } catch (error) {
        fail("opencode", error, start);
      }
    }
    try {
      const port = Number(options.port ?? String(DEFAULT_OPENCODE_PORT));
      if (!Number.isInteger(port) || port <= 0 || port > 65535)
        throw new Error(
          `OPENCODE_PORT_INVALID: ${options.port} is not a valid TCP port`,
        );
      const verifyTimeout = Number(options.verifyTimeout ?? "120");
      if (!Number.isFinite(verifyTimeout) || verifyTimeout <= 0)
        throw new Error(
          `VERIFY_TIMEOUT_INVALID: ${options.verifyTimeout} is not a valid timeout in seconds`,
        );
      const result = await runOpenCodeFlow({
        config: resolveConfig(tailscaleEnv()),
        port,
        yes: Boolean(options.yes),
        dryRun: Boolean(options.dryRun),
        install: Boolean(options.install),
        verify: options.verify !== false,
        verifyTimeout,
        ...(typeof options.opencodeConfig === "string"
          ? { opencodeConfigPath: options.opencodeConfig }
          : {}),
        ...(options.applyPolicy ? { applyPolicy: true } : {}),
        ...(options.enableHttps ? { enableHttps: true } : {}),
        ...(typeof options.credentialEnv === "string"
          ? { credentialEnvName: options.credentialEnv }
          : {}),
        ...(options.tagOwner?.length ? { tagOwner: options.tagOwner } : {}),
        ...(typeof options.backupDir === "string"
          ? { backupDir: options.backupDir }
          : {}),
      });
      const warnings = [...result.deployment.warnings];
      if (result.opencode.permissionWritten.length)
        warnings.push(
          `OPENCODE_PERMISSIONS_WRITTEN: ${result.opencode.permissionWritten.join(", ")} — permission "allow" (headless equivalent of --auto; nothing is blocked)`,
        );
      if (result.opencode.permissionExisting.length)
        warnings.push(
          `OPENCODE_PERMISSIONS_EXISTING: ${result.opencode.permissionExisting.join(", ")} left untouched`,
        );
      const sideEffects = [
        result.opencode.runner.installedBy === "npx-resolved"
          ? "install/resolve opencode-ai via npx"
          : "reuse the opencode binary on PATH",
        "start opencode serve (background)",
        "join tailnet and configure Funnel",
        ...(result.verified ? ["verify public DNS + live TLS endpoint"] : []),
      ];
      const requiredPrivileges = [
        "write ~/.config/opencode and ./opencode.json",
        "npm/npx access for opencode-ai",
        "tailscaled running (userspace auto-started)",
      ];
      emit(
        "opencode",
        result,
        warnings,
        sideEffects,
        requiredPrivileges,
        start,
      );
      const urlsOut = result.urls.length
        ? result.urls.map((url) => `OpenCode URL: ${url}`).join("\n")
        : undefined;
      // --json must keep stdout pure JSON; human-readable URLs go to stderr.
      if (program.opts<{ json?: boolean }>().json) {
        if (urlsOut) console.error(urlsOut);
      } else if (urlsOut) console.log(urlsOut);
    } catch (error) {
      fail("opencode", error, start);
    }
  },
);

void program.parseAsync(process.argv);
