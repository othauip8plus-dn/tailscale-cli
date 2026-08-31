#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { apiCredentialHint, ApiError, TailscaleApiClient } from "./api.js";
import { cleanup } from "./cleanup.js";
import {
  credentialEnvName,
  loadConfigFile,
  maskSecret,
  resolveAuth,
  resolveConfig,
  resolveCredential,
  runtime,
} from "./core.js";
import {
  deploy as deployCommand,
  ensureFunnelReadiness,
  ensureSshReadiness,
  resolveTags,
} from "./deploy.js";
import {
  findTailscale,
  tailscaleVersion,
  TailscaleLocal,
} from "./tailscale.js";
import { startOAuthWrapper } from "./oauth-wrapper.js";
import {
  cacheBinDir,
  installWindowsMsi,
  latestStableInfo,
  latestWindowsInstallInfo,
  updateCacheBinary,
} from "./binary.js";
import {
  ensureDaemon,
  inspectDaemon,
  daemonStatus,
  stopUserspaceDaemon,
} from "./daemon.js";
import { funnelPublicDnsPropagated } from "./dns.js";
import { manifest } from "./manifest.js";
import { sleep } from "./utils.js";
import {
  ensureDeployTags,
  ensureFunnelAccess,
  ensureHttpsEnabled,
  funnelCovered,
  policyFromEnv,
  policySync,
} from "./policy.js";
import type { ResolvedConfig } from "./types.js";
import {
  generateSampleConfig,
  loadServiceConfig,
  maskEnv,
  resolveUserName,
} from "./service/config.js";
import { getServiceManager, getSchedulerManager } from "./service/index.js";
import type { ServiceManager } from "./service/types.js";
import { registryFind } from "./service/registry.js";
import { listeningPortsLinux, lingerEnabled } from "./service/linux.js";
import { isAdminUser } from "./service/windows.js";
import { confirm, promptCredential } from "./interactive.js";
import { verifyEndpointReachable } from "./verify.js";
import type { Envelope } from "./types.js";

function packageVersion(): string {
  try {
    const here = fileURLToPath(new URL(".", import.meta.url));
    const pkg = JSON.parse(
      readFileSync(resolvePath(here, "..", "package.json"), "utf8"),
    ) as { version?: string };
    if (pkg.version) return pkg.version;
  } catch {
    // Fall through to a safe default when package.json is not reachable.
  }
  return "0.0.0";
}

const program = new Command();
program
  .name("tailsacle-cli")
  .description("Safe, zero-config Tailscale deployment CLI")
  .version(packageVersion())
  .option("--json", "emit a stable JSON envelope")
  .option(
    "--config <path>",
    "path to tailscale-cli.config.json (default: auto-detect in cwd)",
  )
  .option(
    "--credential-env <name>",
    "use the Tailscale trust credential found in this env var (overrides auto-detection)",
  )
  .option(
    "--profile <profile>",
    "override the active profile (ci|container|vm|windows|funnel-app|subnet-router|exit-node|dev)",
  )
  .option(
    "--client-secret <secret>",
    "OAuth client secret (overrides TS_CLIENT_SECRET for this run; visible in process listings)",
  )
  .option(
    "--client-id <id>",
    "OAuth client id (overrides TS_CLIENT_ID for this run; visible in process listings)",
  )
  .option(
    "--update-bin",
    "download the latest stable Tailscale client into the package cache",
  );

program.hook("preAction", () => applyCredentialFlags());

async function handleGlobalFlags(): Promise<boolean> {
  const opts = program.opts<CliOptions>();
  if (!opts.updateBin) return false;
  const start = performance.now();
  try {
    if (process.platform === "win32") {
      const result = await installWindowsMsi({});
      emit(
        "update-bin",
        {
          installed: true,
          version: result.version,
          msi: result.msi,
          cachedPath: result.cachedPath,
        },
        ["WINDOWS_MSI_INSTALLED: Tailscale MSI installed silently"],
        ["download Tailscale MSI", "install Tailscale MSI silently"],
        ["windows administrator"],
        start,
      );
    } else {
      const result = await updateCacheBinary({});
      emit(
        "update-bin",
        result,
        [],
        ["download Tailscale client into cache", "update cache binary"],
        [],
        start,
      );
    }
    return true;
  } catch (error) {
    fail("update-bin", error, start);
  }
}

interface CliOptions {
  json?: boolean;
  config?: string;
  credentialEnv?: string;
  profile?: string;
  clientSecret?: string;
  clientId?: string;
  updateBin?: boolean;
}

function configPath(): string | undefined {
  return program.opts<CliOptions>().config;
}

function applyCredentialFlags(): void {
  const opts = program.opts<CliOptions>();
  if ((opts.clientSecret || opts.clientId) && opts.credentialEnv) {
    throw new Error(
      "CREDENTIAL_SELECTION_CONFLICT: choose either --credential-env or --client-secret/--client-id, not both",
    );
  }
  if (opts.clientSecret) {
    process.env.TS_CLIENT_SECRET = opts.clientSecret;
    console.error(
      "CLIENT_SECRET_VIA_FLAG: passing credentials on the command line is visible in process listings; prefer TS_CLIENT_SECRET",
    );
  }
  if (opts.clientId) process.env.TS_CLIENT_ID = opts.clientId;
}

function configEnv(): NodeJS.ProcessEnv {
  const opts = program.opts<CliOptions>();
  let env = process.env;
  const loaded = loadConfigFile(opts.config);
  if (loaded) {
    const fileEnv = { ...env };
    const { config } = loaded;
    if (config.profile && !env.TS_PROFILE) fileEnv.TS_PROFILE = config.profile;
    if (config.tailnet && !env.TS_TAILNET) fileEnv.TS_TAILNET = config.tailnet;
    if (config.hostname && !env.TS_HOSTNAME)
      fileEnv.TS_HOSTNAME = config.hostname;
    if (config.tags?.length && !env.TS_TAGS)
      fileEnv.TS_TAGS = config.tags.join(",");
    if (config.ssh !== undefined && env.TS_SSH === undefined)
      fileEnv.TS_SSH = String(config.ssh);
    if (config.keyExpiry && !env.TS_KEY_EXPIRY)
      fileEnv.TS_KEY_EXPIRY = config.keyExpiry;
    if (
      config.preauthorized !== undefined &&
      env.TS_PREAUTHORIZED === undefined
    )
      fileEnv.TS_PREAUTHORIZED = String(config.preauthorized);
    if (config.reusable !== undefined && env.TS_REUSABLE === undefined)
      fileEnv.TS_REUSABLE = String(config.reusable);
    if (config.ephemeral !== undefined && env.TS_EPHEMERAL === undefined)
      fileEnv.TS_EPHEMERAL = String(config.ephemeral);
    if (config.acceptDns !== undefined && env.TS_ACCEPT_DNS === undefined)
      fileEnv.TS_ACCEPT_DNS = String(config.acceptDns);
    if (config.acceptRoutes !== undefined && env.TS_ACCEPT_ROUTES === undefined)
      fileEnv.TS_ACCEPT_ROUTES = String(config.acceptRoutes);
    if (
      config.cleanupAfter !== undefined &&
      env.TS_CLEANUP_OFFLINE_AFTER === undefined
    )
      fileEnv.TS_CLEANUP_OFFLINE_AFTER = String(config.cleanupAfter);
    if (config.credentialEnv && !env.TS_CREDENTIAL_ENV)
      fileEnv.TS_CREDENTIAL_ENV = config.credentialEnv;
    if (config.clientSecret && !env.TS_CLIENT_SECRET)
      fileEnv.TS_CLIENT_SECRET = config.clientSecret;
    if (config.tagOwner?.length && !env.TS_TAG_OWNER)
      fileEnv.TS_TAG_OWNER = config.tagOwner.join(",");
    env = fileEnv;
  }
  if (opts.profile) {
    const valid = [
      "ci",
      "container",
      "vm",
      "windows",
      "funnel-app",
      "subnet-router",
      "exit-node",
      "dev",
    ];
    if (!valid.includes(opts.profile))
      throw new Error(`PROFILE_INVALID: expected one of ${valid.join(", ")}`);
    env = { ...env, TS_PROFILE: opts.profile };
  }
  return env;
}

function resolvedCredentialEnv(): string | undefined {
  const opts = program.opts<CliOptions>();
  const env = configEnv();
  const name = opts.credentialEnv ?? env.TS_CREDENTIAL_ENV?.trim();
  if (name) {
    const value = env[name]?.trim();
    if (!value)
      throw new Error(`CREDENTIAL_ENV_MISSING: env ${name} is not set`);
    if (!value.startsWith("tskey-client-"))
      throw new Error(
        `CREDENTIAL_FORMAT_UNSUPPORTED: env ${name} is not a tskey-client- trust credential`,
      );
    return name;
  }
  return credentialEnvName(env);
}

function envTagOwner(): string[] | undefined {
  const value = process.env.TS_TAG_OWNER?.trim();
  if (!value) return undefined;
  return value
    .split(",")
    .map((owner) => owner.trim())
    .filter(Boolean);
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
  process.exitCode = 0;
}

function fail(
  command: string,
  error: unknown,
  start = performance.now(),
): never {
  const detail =
    error instanceof ApiError
      ? {
          code: error.code,
          message: error.message,
          retryable: error.retryable,
          status: error.status,
        }
      : {
          code: "CLI_ERROR",
          message: error instanceof Error ? error.message : String(error),
          retryable: false,
          status: undefined,
        };
  const docsUrl = ERROR_DOCS[detail.code];
  const envelope: Envelope<never> = {
    ok: false,
    command,
    durationMs: Math.round(performance.now() - start),
    warnings: [],
    requiredPrivileges: [],
    sideEffects: [],
    retryable: detail.retryable,
    error: {
      code: detail.code,
      message: detail.message,
      ...(detail.status ? { status: detail.status } : {}),
      ...(docsUrl ? { docsUrl } : {}),
    },
  };
  if (program.opts<{ json?: boolean }>().json)
    console.error(JSON.stringify(envelope, null, 2));
  else {
    const suffix = docsUrl ? ` (see ${docsUrl})` : "";
    console.error(`${detail.code}: ${detail.message}${suffix}`);
  }
  process.exitCode = detail.retryable ? 75 : exitCodeFor(error);
  throw error;
}

function exitCodeFor(error: unknown): number {
  if (error instanceof ApiError) {
    if (error.status === 401 || error.status === 403) return 4;
    if (error.retryable) return 75;
    return 1;
  }
  const message = error instanceof Error ? error.message : String(error);
  if (/AUTH|CREDENTIAL/.test(message)) return 3;
  if (/TAILSCALE_BINARY|BIN_|CHECKSUM/.test(message)) return 5;
  if (/TAILSCALE_NOT_RUNNING|AUTH_KEY/.test(message)) return 6;
  if (/FUNNEL|SERVE|VERIFY|TLS|DNS_PUBLIC/.test(message)) return 7;
  if (/POLICY/.test(message)) return 8;
  if (/PRIVILEGE|PERMISSION_DENIED|root|administrator/i.test(message)) return 9;
  return 1;
}

const DOCS_BASE =
  "https://github.com/ongtrieuphuchieu689-7u/tailscale-cli/blob/main/docs";
const ERROR_DOCS: Record<string, string> = {
  CREDENTIAL_NOT_FOUND: `${DOCS_BASE}/user_requirement.md#credential-resolution`,
  CREDENTIAL_AMBIGUOUS: `${DOCS_BASE}/user_requirement.md#credential-resolution`,
  CREDENTIAL_FORMAT_UNSUPPORTED: `${DOCS_BASE}/user_requirement.md#credential-resolution`,
  CREDENTIAL_ENV_MISSING: `${DOCS_BASE}/user_requirement.md#credential-resolution`,
  TAILSCALE_BINARY_NOT_FOUND: `${DOCS_BASE}/user_requirement.md#binary-management`,
  TAILSCALE_NOT_RUNNING: `${DOCS_BASE}/user_requirement.md#daemon-management`,
  FUNNEL_EPHEMERAL: `${DOCS_BASE}/user_requirement.md#funnel`,
  FUNNEL_TARGET_REQUIRED: `${DOCS_BASE}/user_requirement.md#funnel`,
  FUNNEL_PORT_UNSUPPORTED: `${DOCS_BASE}/user_requirement.md#funnel`,
  FUNNEL_ATTR_REQUIRED: `${DOCS_BASE}/user_requirement.md#funnel`,
  FUNNEL_DNS_NOT_PUBLISHED: `${DOCS_BASE}/user_requirement.md#funnel`,
  FUNNEL_ENDPOINT_UNREACHABLE: `${DOCS_BASE}/user_requirement.md#funnel`,
  DNS_MAGICDNS_CONFIRMATION_REQUIRED: `${DOCS_BASE}/user_requirement.md#dns`,
  POLICY_FILE_REQUIRED: `${DOCS_BASE}/user_requirement.md#policy`,
  POLICY_VERIFY_FAILED: `${DOCS_BASE}/user_requirement.md#policy`,
  PRIVILEGE_REQUIRED: `${DOCS_BASE}/user_requirement.md#privileges`,
};

async function credentialFromOptions(): Promise<
  ReturnType<typeof resolveCredential>
> {
  const opts = program.opts<CliOptions>();
  const env = configEnv();
  const name = opts.credentialEnv ?? env.TS_CREDENTIAL_ENV?.trim();
  if (!name) {
    const resolution = resolveCredential(env);
    if (!resolution.found && resolution.error === "CREDENTIAL_NOT_FOUND") {
      const prompted = await promptCredential();
      if (prompted && prompted.startsWith("tskey-client-")) {
        process.env.TS_CLIENT_SECRET = prompted;
        return {
          found: true,
          source: "interactive-prompt",
          masked: maskSecret(prompted),
          candidates: resolution.candidates,
        };
      }
    }
    return resolution;
  }
  const value = env[name]?.trim();
  if (!value)
    return {
      found: false,
      candidates: [name],
      error: "CREDENTIAL_ENV_MISSING",
    };
  if (!value.startsWith("tskey-client-"))
    return {
      found: false,
      candidates: [name],
      error: "CREDENTIAL_FORMAT_UNSUPPORTED",
    };
  return {
    found: true,
    source: name,
    masked: maskSecret(value),
    candidates: [],
  };
}

function authFromOptions(): ReturnType<typeof resolveAuth> {
  const opts = program.opts<CliOptions>();
  const env = configEnv();
  const name = opts.credentialEnv ?? env.TS_CREDENTIAL_ENV?.trim();
  if (!name) return resolveAuth(env);
  const value = env[name]?.trim();
  if (!value)
    return {
      found: false,
      candidates: [name],
      error: "CREDENTIAL_ENV_MISSING",
    };
  if (!value.startsWith("tskey-client-"))
    return {
      found: false,
      candidates: [name],
      error: "CREDENTIAL_FORMAT_UNSUPPORTED",
    };
  return {
    found: true,
    auth: {
      kind: "oauth-trust",
      source: name,
      masked: maskSecret(value),
    },
    candidates: [],
  };
}

async function probeScope(
  fn: () => Promise<unknown>,
): Promise<"ok" | "missing-scope" | "error"> {
  try {
    await fn();
    return "ok";
  } catch (error) {
    if (error instanceof ApiError && [401, 403].includes(error.status))
      return "missing-scope";
    return "error";
  }
}

async function deepDoctor(
  config: ResolvedConfig,
  options: { credentialEnvName?: string },
): Promise<{
  scopes: Record<string, string>;
  httpsEnabled?: boolean;
  funnelReady?: boolean;
  magicDNS?: boolean;
  daemon: { running: boolean; actions: string[] };
  isRoot: boolean;
}> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const beacon: Record<string, string> = {};
  if (!api.hasCredentials()) beacon.error = "CREDENTIAL_NOT_FOUND";
  const result: {
    scopes: Record<string, string>;
    httpsEnabled?: boolean;
    funnelReady?: boolean;
    magicDNS?: boolean;
    daemon: { running: boolean; actions: string[] };
    isRoot: boolean;
  } = {
    scopes: beacon,
    daemon: await inspectDaemon(),
    isRoot:
      typeof process.getuid === "function" ? process.getuid() === 0 : false,
  };
  if (!api.hasCredentials()) return result;

  result.scopes.devicesCore = await probeScope(() => api.listDevices());
  result.scopes.policyFile = await probeScope(() => api.getPolicy());
  const dnsScope = await probeScope(async () => {
    const dns = await api.getDns();
    const preferences = dns.preferences as { magicDNS?: boolean } | undefined;
    result.magicDNS = preferences?.magicDNS === true;
  });
  result.scopes.dns = dnsScope;
  result.scopes.all = await probeScope(async () => {
    const settings = await api.getTailnetSettings();
    if (settings.httpsEnabled !== undefined)
      result.httpsEnabled = settings.httpsEnabled;
  });
  if (result.scopes.policyFile === "ok") {
    try {
      const policy = await api.getPolicy();
      result.funnelReady = funnelCovered(policy.json, config.tags);
    } catch {
      // funnelReady stays undefined when the read fails.
    }
  }
  return result;
}

program
  .command("doctor")
  .description(
    "Resolve credentials, runtime, local binary and API capability without remote side effects",
  )
  .option("--detect-credentials")
  .option("--show-resolution")
  .option("--deep", "run read-only API capability probes (no side effects)")
  .action(async (options: { deep?: boolean }) => {
    const start = performance.now();
    try {
      const config = resolveConfig(configEnv());
      const credential = await credentialFromOptions();
      const auth = authFromOptions();
      let binary: unknown = { found: false };
      try {
        binary = await tailscaleVersion(undefined, { download: false });
      } catch (error) {
        binary = {
          found: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
      const warnings = [...config.warnings];
      if (!auth.found)
        warnings.push(
          auth.error === "MULTIPLE_CREDENTIALS"
            ? "CREDENTIAL_AMBIGUOUS: choose a credential explicitly with --credential-env"
            : "CREDENTIAL_NOT_FOUND",
        );
      if (apiCredentialHint() === "missing")
        warnings.push(
          "API_CREDENTIAL_NOT_CONFIGURED: deploy can still use TS_AUTH_KEY",
        );
      let deep: Record<string, unknown> | undefined;
      if (options.deep) {
        const credentialEnv = resolvedCredentialEnv();
        deep = await deepDoctor(config, {
          ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
        });
        const scopes = deep.scopes as Record<string, string>;
        if (deep.httpsEnabled === false)
          warnings.push(
            "HTTPS_DISABLED: tailnet HTTPS is disabled; Funnel/Serve will not work until it is enabled",
          );
        if (deep.funnelReady === false)
          warnings.push(
            "FUNNEL_ATTR_MISSING: the funnel node attribute is not set for the deployment tags; run a funnel flow with --apply-policy",
          );
        if (scopes.devicesCore === "missing-scope")
          warnings.push("API_SCOPE_MISSING: devices:core scope is not granted");
        if (scopes.policyFile === "missing-scope")
          warnings.push(
            "API_SCOPE_MISSING: policy_file scope is not granted (funnel/tag provisioning will fail)",
          );
        if (scopes.dns === "missing-scope")
          warnings.push("API_SCOPE_MISSING: dns scope is not granted");
        if (scopes.all === "missing-scope")
          warnings.push(
            "API_SCOPE_MISSING: all scope is not granted (tailnet HTTPS cannot be enabled)",
          );
      }
      emit(
        "doctor",
        {
          config,
          credential,
          auth,
          apiCredential: apiCredentialHint(),
          binary,
          runtime,
          ...(deep ? { deep } : {}),
        },
        warnings,
        [],
        [],
        start,
      );
    } catch (error) {
      fail("doctor", error, start);
    }
  });

program
  .command("deploy")
  .description("Join the tailnet and optionally configure Serve/Funnel")
  .option("--dry-run")
  .option("--yes")
  .option("--expose <target...>")
  .option("--funnel")
  .option("--apply-policy")
  .option("--enable-https")
  .option("--cleanup")
  .option("--bin <path>")
  .option("--ssh", "enable Tailscale SSH on this node (default: true)")
  .option("--no-ssh", "disable Tailscale SSH on this node")
  .option("--state-dir <path>", "state directory for tailscaled")
  .option(
    "--backup-dir <path>",
    "directory for policy backups (default: ./.tailscale-cli)",
  )
  .option(
    "--key-expiry <value>",
    "auth-key expiry: max (documented 90-day ceiling), unlimited, or seconds",
  )
  .option(
    "--tag-owner <owner...>",
    "owner(s) for auto-provisioned tagOwners (otherwise derived from a single existing owner set)",
  )
  .action(
    async (options: {
      dryRun?: boolean;
      yes?: boolean;
      expose?: string[];
      funnel?: boolean;
      applyPolicy?: boolean;
      enableHttps?: boolean;
      cleanup?: boolean;
      bin?: string;
      ssh?: boolean;
      stateDir?: string;
      backupDir?: string;
      keyExpiry?: string;
      tagOwner?: string[];
    }) => {
      const start = performance.now();
      try {
        if (options.keyExpiry) process.env.TS_KEY_EXPIRY = options.keyExpiry;
        const credentialEnv = resolvedCredentialEnv();
        const tagOwner = options.tagOwner ?? envTagOwner();
        const config = resolveConfig(configEnv());
        if (options.ssh !== undefined) config.ssh = options.ssh;
        if (options.stateDir) config.stateDir = options.stateDir;
        const result = await deployCommand(config, {
          dryRun: Boolean(options.dryRun),
          yes: Boolean(options.yes),
          expose: options.expose ?? [],
          funnel: Boolean(options.funnel),
          applyPolicy: Boolean(options.applyPolicy),
          enableHttps: Boolean(options.enableHttps),
          cleanup: Boolean(options.cleanup),
          ...(options.bin ? { bin: options.bin } : {}),
          ...(options.backupDir ? { backupDir: options.backupDir } : {}),
          ...(tagOwner?.length ? { tagOwner } : {}),
          ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
        });
        emit(
          "deploy",
          result,
          [...config.warnings, ...result.warnings],
          options.dryRun
            ? []
            : [
                "authenticate node",
                "configure Tailscale state",
                ...(result.exposures.length ? ["configure Serve/Funnel"] : []),
                ...(result.warnings.length ? ["update tailnet policy"] : []),
              ],
          process.platform === "win32"
            ? []
            : ["root/admin may be required by tailscaled"],
          start,
        );
      } catch (error) {
        fail("deploy", error, start);
      }
    },
  );

program
  .command("up")
  .description("Alias for deploy without exposure configuration")
  .option("--dry-run")
  .option("--yes")
  .option("--apply-policy")
  .option("--cleanup")
  .option("--ssh", "enable Tailscale SSH on this node (default: true)")
  .option("--no-ssh", "disable Tailscale SSH on this node")
  .option("--state-dir <path>", "state directory for tailscaled")
  .option(
    "--backup-dir <path>",
    "directory for policy backups (default: ./.tailscale-cli)",
  )
  .option(
    "--key-expiry <value>",
    "auth-key expiry: max (documented 90-day ceiling), unlimited, or seconds",
  )
  .option(
    "--tag-owner <owner...>",
    "owner(s) for auto-provisioned tagOwners (otherwise derived from a single existing owner set)",
  )
  .action(
    async (options: {
      dryRun?: boolean;
      yes?: boolean;
      applyPolicy?: boolean;
      cleanup?: boolean;
      ssh?: boolean;
      stateDir?: string;
      backupDir?: string;
      keyExpiry?: string;
      tagOwner?: string[];
    }) => {
      const start = performance.now();
      try {
        if (options.keyExpiry) process.env.TS_KEY_EXPIRY = options.keyExpiry;
        const credentialEnv = resolvedCredentialEnv();
        const tagOwner = options.tagOwner ?? envTagOwner();
        const config = resolveConfig(configEnv());
        if (options.ssh !== undefined) config.ssh = options.ssh;
        if (options.stateDir) config.stateDir = options.stateDir;
        const result = await deployCommand(config, {
          dryRun: Boolean(options.dryRun),
          yes: Boolean(options.yes),
          expose: [],
          funnel: false,
          applyPolicy: Boolean(options.applyPolicy),
          cleanup: Boolean(options.cleanup),
          ...(options.backupDir ? { backupDir: options.backupDir } : {}),
          ...(tagOwner?.length ? { tagOwner } : {}),
          ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
        });
        emit(
          "up",
          result,
          result.warnings,
          options.dryRun
            ? []
            : [
                "authenticate node",
                "configure Tailscale state",
                ...(result.cleanup && result.cleanup.deleted.length
                  ? ["delete offline devices"]
                  : []),
              ],
          process.platform === "win32"
            ? []
            : ["root/admin may be required by tailscaled"],
          start,
        );
      } catch (error) {
        fail("up", error, start);
      }
    },
  );

program
  .command("status")
  .description("Show local Tailscale status")
  .option(
    "--show-resolution",
    "include credential resolution source and masked value",
  )
  .action(async (options: { showResolution?: boolean }) => {
    const start = performance.now();
    try {
      const local = new TailscaleLocal(await findTailscale());
      const statusResult = await local.status();
      const resolved = options.showResolution
        ? { status: statusResult, credential: await credentialFromOptions() }
        : statusResult;
      emit("status", resolved, [], [], [], start);
    } catch (error) {
      fail("status", error, start);
    }
  });

program
  .command("update-bin")
  .description(
    "Download the latest stable Tailscale client into the package cache (never overwrites package-managed binaries)",
  )
  .option("--yes")
  .option("--dry-run")
  .option("--force")
  .option("--skip-checksum")
  .option("--track <track>")
  .action(
    async (options: {
      yes?: boolean;
      dryRun?: boolean;
      force?: boolean;
      skipChecksum?: boolean;
      track?: string;
    }) => {
      const start = performance.now();
      try {
        if (options.track && options.track !== "stable")
          throw new Error(
            "BIN_TRACK_UNSUPPORTED: only the stable track is supported",
          );
        if (process.platform === "win32") {
          if (options.dryRun) {
            const info = await latestWindowsInstallInfo();
            emit(
              "update-bin",
              { latest: info.version, msi: info.msi, dryRun: true },
              [
                "WINDOWS_MSI_BOOTSTRAP: the package downloads and silently installs the MSI; an Administrator shell is required",
              ],
              [],
              [],
              start,
            );
            return;
          }
          const result = await installWindowsMsi({
            ...(options.skipChecksum ? { skipChecksum: true } : {}),
          });
          const warnings = [
            ...(options.skipChecksum
              ? [
                  "BIN_CHECKSUM_SKIPPED: --skip-checksum disables the MSI download integrity check",
                ]
              : []),
            "WINDOWS_MSI_INSTALLED: Tailscale MSI installed silently",
          ];
          emit(
            "update-bin",
            {
              installed: true,
              version: result.version,
              msi: result.msi,
              cachedPath: result.cachedPath,
            },
            warnings,
            ["download Tailscale MSI", "install Tailscale MSI silently"],
            ["windows administrator"],
            start,
          );
          return;
        }
        if (options.dryRun) {
          const info = await latestStableInfo();
          emit(
            "update-bin",
            { latest: info.version, dryRun: true },
            [],
            [],
            [],
            start,
          );
          return;
        }
        const result = await updateCacheBinary({
          ...(options.force ? { force: true } : {}),
          ...(options.skipChecksum ? { skipChecksum: true } : {}),
        });
        emit(
          "update-bin",
          result,
          options.skipChecksum
            ? [
                "BIN_CHECKSUM_SKIPPED: --skip-checksum disables the download integrity check",
              ]
            : [],
          ["download Tailscale client into cache", "update cache binary"],
          [],
          start,
        );
      } catch (error) {
        fail("update-bin", error, start);
      }
    },
  );

async function funnelDnsName(
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

interface FunnelOptions {
  https?: string;
  tcp?: string;
  path?: string;
  expose?: string[];
  yes?: boolean;
  applyPolicy?: boolean;
  enableHttps?: boolean;
  verifyTimeout?: number;
  ssh?: boolean;
  stateDir?: string;
}

function parseFunnelExpose(value: string): {
  https: number;
  path?: string;
  target: string;
} {
  const eq = value.trim().split("=", 2);
  const localPort = eq[1] ? Number(eq[1].trim()) : undefined;
  const left = eq[0]!.replace(/^[,;]\s*/, "");
  const slash = left.indexOf("/");
  const https = Number(slash >= 0 ? left.slice(0, slash) : left);
  if (!Number.isFinite(https) || ![443, 8443, 10000].includes(https))
    throw new Error(
      "FUNNEL_PORT_UNSUPPORTED: Funnel allows 443, 8443, or 10000",
    );
  if (!localPort || !Number.isFinite(localPort))
    throw new Error(
      `FUNNEL_EXPOSE_INVALID: ${value} (expected "443=3000" or "443/api=3001")`,
    );
  const path =
    slash >= 0
      ? left.slice(slash).startsWith("/")
        ? left.slice(slash)
        : `/${left.slice(slash)}`
      : undefined;
  return {
    https,
    ...(path ? { path } : {}),
    target: `http://127.0.0.1:${localPort}`,
  };
}

program
  .command("funnel")
  .description(
    "Configure Tailscale Funnel for a target (auto-detects target and verifies public DNS plus the live TLS/TCP endpoint)",
  )
  .argument(
    "[target]",
    "local target such as 3000, localhost:8080 or http://127.0.0.1:3000 (defaults to $PORT)",
  )
  .option("--https <port>", "public HTTPS port (443, 8443 or 10000)")
  .option("--tcp <public:local>", "TCP funnel instead of HTTPS")
  .option("--path <path>")
  .option(
    "--expose <target...>",
    'repeatable expose targets, e.g. "443=3000" or "443/api=3001"',
  )
  .option("--yes")
  .option("--apply-policy")
  .option("--enable-https")
  .option("--ssh", "enable Tailscale SSH on this node (default: true)")
  .option("--no-ssh", "disable Tailscale SSH on this node")
  .option("--state-dir <path>", "state directory for tailscaled")
  .option(
    "--verify-timeout <sec>",
    "public DNS and live-endpoint verification timeout",
  )
  .action(async (target: string | undefined, options: FunnelOptions) => {
    const start = performance.now();
    try {
      const config = resolveConfig(configEnv());
      if (options.ssh !== undefined) config.ssh = options.ssh;
      if (options.stateDir) config.stateDir = options.stateDir;
      const local = new TailscaleLocal(await findTailscale());
      const credentialEnvNameResolved = resolvedCredentialEnv();
      const httpsPort = options.https ? Number(options.https) : 443;
      if (options.https && ![443, 8443, 10000].includes(httpsPort))
        throw new Error(
          "FUNNEL_PORT_UNSUPPORTED: Funnel allows 443, 8443, or 10000",
        );

      const warnings: string[] = [];
      const { tags: deploymentTags, autoTagged } = resolveTags(config);
      if (autoTagged)
        warnings.push(
          `AUTO_TAG: no TS_TAGS configured; using deterministic tag ${deploymentTags[0]} (override with TS_TAGS)`,
        );
      if (config.ephemeral)
        throw new Error(
          "FUNNEL_EPHEMERAL: the node is ephemeral so Funnel will never publish public DNS; set TS_EPHEMERAL=false (or use TS_PROFILE=funnel-app which defaults to non-ephemeral) and re-run",
        );
      const daemon = await ensureDaemon(
        config.stateDir ? { stateDir: config.stateDir } : undefined,
      );
      if (!daemon.running) warnings.push(...daemon.warnings);
      const exposed = (options.expose ?? [])
        .filter(Boolean)
        .map(parseFunnelExpose);
      if (options.yes && options.applyPolicy) {
        const readiness = await ensureFunnelReadiness(config, deploymentTags, {
          yes: true,
          applyPolicy: true,
          ...(credentialEnvNameResolved
            ? { credentialEnvName: credentialEnvNameResolved }
            : {}),
        });
        warnings.push(...readiness);
        if (config.ssh) {
          const sshReadiness = await ensureSshReadiness(
            config,
            deploymentTags,
            {
              yes: true,
              applyPolicy: true,
              ...(credentialEnvNameResolved
                ? { credentialEnvName: credentialEnvNameResolved }
                : {}),
            },
          );
          warnings.push(...sshReadiness);
        }
      }
      let resolvedTarget = target;
      const verifySeconds = options.verifyTimeout
        ? Number(options.verifyTimeout)
        : 120;
      if (options.tcp) {
        const [publicPort, localPort] = options.tcp
          .replace(/\s/g, "")
          .split(":");
        if (!publicPort || !localPort)
          throw new Error(
            "FUNNEL_TCP_INVALID: --tcp expects public:local, e.g. 10000:5432",
          );
        await local.funnel([
          "--bg",
          `--tcp=${publicPort}`,
          `tcp://127.0.0.1:${localPort}`,
        ]);
        const name = await funnelDnsName(local);
        const verify = name
          ? await funnelPublicDnsPropagated(name, verifySeconds)
          : { ok: false as const, attempts: 0 };
        if (!verify.ok)
          throw new Error(
            `FUNNEL_DNS_NOT_PUBLISHED: no public DNS record for ${name ?? "the funnel hostname"} within ${verifySeconds}s (tried ${verify.attempts} times)`,
          );
        const endpoint = name
          ? await verifyEndpointReachable(
              name,
              [Number(publicPort)],
              "tcp",
              verifySeconds,
            )
          : { ok: false as const, verifiedPorts: [], attempts: 0 };
        if (!endpoint.ok)
          throw new Error(
            `FUNNEL_ENDPOINT_UNREACHABLE: public DNS resolved for ${name} but the TCP endpoint ${name}:${publicPort} did not accept connections within ${verifySeconds}s (tried ${endpoint.attempts} times${endpoint.lastError ? `; last error: ${endpoint.lastError}` : ""})`,
          );
        emit(
          "funnel",
          {
            target: `tcp://127.0.0.1:${localPort}`,
            localTarget: `tcp://127.0.0.1:${localPort}`,
            public: true,
            tcp: Number(publicPort),
            publicPort: Number(publicPort),
            ...(name
              ? {
                  endpoint: `${name}:${publicPort}`,
                  url: `${name}:${publicPort}`,
                }
              : {}),
            verified: true,
            dnsPropagated: true,
            dnsAttempts: verify.attempts,
            tcpVerified: true,
            verifyAttempts: endpoint.attempts,
          },
          warnings,
          ["configure Funnel (TCP)", "verify public listener & DNS"],
          [],
          start,
        );
        return;
      }
      if (!exposed.length) {
        resolvedTarget =
          target ??
          (process.env.PORT
            ? `http://127.0.0.1:${process.env.PORT}`
            : undefined);
        if (!resolvedTarget)
          throw new Error(
            "FUNNEL_TARGET_REQUIRED: pass a target, --expose, or set $PORT",
          );
        if (!target)
          warnings.push(
            `FUNNEL_TARGET_DEFAULTED: used $PORT=${process.env.PORT} as the local target; override with a positional target or --expose`,
          );
      }

      if (options.yes && options.enableHttps) {
        const https = await ensureHttpsEnabled(config, {
          yes: true,
          ...(credentialEnvNameResolved
            ? { credentialEnvName: credentialEnvNameResolved }
            : {}),
        });
        warnings.push(...https.warnings);
      }
      const runFunnel = async (extra: string[]): Promise<void> => {
        await local.funnel(["--bg", "--yes", ...extra]);
      };
      try {
        if (exposed.length) {
          for (const exposure of exposed) {
            const cmd: string[] = [`--https=${exposure.https}`];
            if (exposure.path) cmd.push(`--set-path=${exposure.path}`);
            await runFunnel(cmd.concat(exposure.target));
          }
        } else {
          const cmd: string[] = [`--https=${httpsPort}`];
          if (options.path)
            cmd.push(
              `--set-path=${options.path.startsWith("/") ? options.path : `/${options.path}`}`,
            );
          await runFunnel(cmd.concat(resolvedTarget as string));
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (
          !/funnel.*(not available|node attribute not set)/i.test(message) ||
          !options.yes
        )
          throw error;
        if (!options.applyPolicy)
          throw new Error(
            "FUNNEL_ATTR_REQUIRED: the funnel node attribute is missing; re-run with --apply-policy to auto-add it on the tailnet",
          );
        warnings.push(
          "SIDE_EFFECT_PLAN: adding the funnel node attribute for the deployment tags before retrying",
        );
        const provisioned = await ensureFunnelAccess(config, deploymentTags, {
          yes: true,
          ...(credentialEnvNameResolved
            ? { credentialEnvName: credentialEnvNameResolved }
            : {}),
        });
        warnings.push(...provisioned.warnings);
        for (let attempt = 0; attempt < 4; attempt += 1) {
          try {
            if (exposed.length) {
              for (const exposure of exposed) {
                const cmd: string[] = [`--https=${exposure.https}`];
                if (exposure.path) cmd.push(`--set-path=${exposure.path}`);
                await runFunnel(cmd.concat(exposure.target));
              }
            } else {
              const cmd: string[] = [`--https=${httpsPort}`];
              if (options.path)
                cmd.push(
                  `--set-path=${options.path.startsWith("/") ? options.path : `/${options.path}`}`,
                );
              await runFunnel(cmd.concat(resolvedTarget as string));
            }
            break;
          } catch (retryError) {
            if (attempt === 3) throw retryError;
            await sleep(3000);
          }
        }
      }

      const name = await funnelDnsName(local);
      const verify = name
        ? await funnelPublicDnsPropagated(name, verifySeconds)
        : { ok: false as const, attempts: 0 };
      if (!verify.ok)
        throw new Error(
          `FUNNEL_DNS_NOT_PUBLISHED: no public DNS record for ${name ?? "the funnel hostname"} within ${verifySeconds}s (tried ${verify.attempts} times)`,
        );
      const publicPorts = [
        ...new Set(
          exposed.length
            ? exposed.map((exposure) => exposure.https)
            : [httpsPort],
        ),
      ];
      const endpoint = name
        ? await verifyEndpointReachable(name, publicPorts, "tls", verifySeconds)
        : { ok: false as const, verifiedPorts: [], attempts: 0 };
      if (!endpoint.ok) {
        const unreachable = publicPorts.filter(
          (port) => !endpoint.verifiedPorts.includes(port),
        );
        throw new Error(
          `FUNNEL_ENDPOINT_UNREACHABLE: public DNS resolved for ${name} but TLS/HTTPS was not reachable on ${unreachable.map((port) => `${name}:${port}`).join(", ")} within ${verifySeconds}s (tried ${endpoint.attempts} times${endpoint.lastError ? `; last error: ${endpoint.lastError}` : ""})`,
        );
      }
      const baseUrl = name ? `https://${name}` : undefined;
      const pathFor = (value: string | undefined): string => value ?? "/";
      const exposures = exposed.length
        ? exposed.map((exposure) => ({
            publicPort: exposure.https,
            path: pathFor(exposure.path),
            localTarget: exposure.target,
            ...(baseUrl ? { url: `${baseUrl}${pathFor(exposure.path)}` } : {}),
          }))
        : [
            {
              publicPort: httpsPort,
              path: pathFor(options.path),
              localTarget: resolvedTarget as string,
              ...(baseUrl ? { url: `${baseUrl}${pathFor(options.path)}` } : {}),
            },
          ];
      emit(
        "funnel",
        {
          target: exposed.length ? exposed[0]!.target : resolvedTarget,
          public: true,
          ...(exposed.length === 0
            ? {
                https: httpsPort,
                path: pathFor(options.path),
                ...(baseUrl ? { url: exposures[0]!.url } : {}),
              }
            : {}),
          exposures,
          verified: true,
          dnsPropagated: true,
          dnsAttempts: verify.attempts,
          tlsVerified: true,
          tlsVerifiedPorts: endpoint.verifiedPorts,
          verifyAttempts: endpoint.attempts,
        },
        warnings,
        [
          "configure Funnel",
          ...(warnings.some((w) => w.startsWith("PROVISIONED"))
            ? ["update tailnet policy", "enable HTTPS"]
            : []),
        ],
        [],
        start,
      );
    } catch (error) {
      fail("funnel", error, start);
    }
  });

program
  .command("serve")
  .description("Configure Tailscale Serve for a target")
  .argument("<target>")
  .option("--https <port>")
  .option("--http <port>")
  .option("--tcp <port>")
  .option("--path <path>")
  .action(
    async (
      target: string,
      options: { https?: string; http?: string; tcp?: string; path?: string },
    ) => {
      const start = performance.now();
      try {
        const local = new TailscaleLocal(await findTailscale());
        const args = ["--bg", "--yes"];
        if (options.https) args.push(`--https=${Number(options.https)}`);
        else if (options.http) args.push(`--http=${Number(options.http)}`);
        else if (options.tcp) args.push(`--tcp=${Number(options.tcp)}`);
        if (options.path)
          args.push(
            `--set-path=${options.path.startsWith("/") ? options.path : `/${options.path}`}`,
          );
        await local.serve([...args, target]);
        emit(
          "serve",
          { target, public: false, path: options.path ?? "/" },
          [],
          ["configure Serve"],
          [],
          start,
        );
      } catch (error) {
        fail("serve", error, start);
      }
    },
  );

import {
  startRelay,
  startMultiRelay,
  parseRelayMapping,
  loadRelayConfigFile,
  type RelayMapping,
  type MultiRelayInstance,
} from "./relay.js";
import {
  resolveNexqlMcpRunner,
  preflightTcpCheck,
  startNexqlMcpHttp,
  stopNexqlMcpHttp,
  registerRelayProfiles,
  maskConnString,
  maskToken,
  randomToken,
  type NexqlMcpRunner,
} from "./nexql-mcp.js";

program
  .command("relay")
  .description(
    "Run a TCP relay proxy to forward connections to another machine (single or multi-port, or via config file)",
  )
  .option("-l, --listen <port>", "local listen port (e.g. 5432)")
  .option(
    "-t, --target <host:port>",
    "target machine host:port (e.g. 100.x.y.z:5432 or other-host:5432)",
  )
  .option(
    "-m, --map <mapping...>",
    "repeatable port mappings, e.g. '5432:5433', '5432:192.168.50.79:5433', or '0.0.0.0:5432:host:5433'",
  )
  .option(
    "-f, --file <configPath>",
    "path to JSON configuration file defining array of relay mappings",
  )
  .option(
    "--host <address>",
    "default listen host (default: 0.0.0.0)",
    "0.0.0.0",
  )
  .option(
    "--target-host <address>",
    "default target host when using simple listen:targetPort mappings",
    "127.0.0.1",
  )
  .option(
    "--serve",
    "also configure tailscale serve for all relay ports in the tailnet",
  )
  .option(
    "--funnel",
    "also configure tailscale funnel for all relay ports publicly (requires --serve)",
  )
  .action(
    async (options: {
      listen?: string;
      target?: string;
      map?: string[];
      file?: string;
      host?: string;
      targetHost?: string;
      serve?: boolean;
      funnel?: boolean;
    }) => {
      const start = performance.now();
      try {
        const mappings: RelayMapping[] = [];

        // 1. From config file
        if (options.file) {
          mappings.push(...loadRelayConfigFile(options.file));
        }

        // 2. From --map flags
        if (options.map && options.map.length > 0) {
          for (const m of options.map) {
            mappings.push(
              parseRelayMapping(m, options.targetHost ?? "127.0.0.1"),
            );
          }
        }

        // 3. From individual --listen & --target
        if (options.listen && options.target) {
          const listenPort = Number(options.listen);
          if (
            !Number.isFinite(listenPort) ||
            listenPort <= 0 ||
            listenPort > 65535
          ) {
            throw new Error(
              `RELAY_PORT_INVALID: --listen must be a valid port number (1-65535), got ${options.listen}`,
            );
          }

          const targetParts = options.target.split(":");
          if (targetParts.length !== 2) {
            throw new Error(
              `RELAY_TARGET_INVALID: --target must be format host:port, got ${options.target}`,
            );
          }
          const targetHost = targetParts[0]!.trim();
          const targetPort = Number(targetParts[1]!.trim());
          if (
            !targetHost ||
            !Number.isFinite(targetPort) ||
            targetPort <= 0 ||
            targetPort > 65535
          ) {
            throw new Error(
              `RELAY_TARGET_INVALID: invalid host or port in --target ${options.target}`,
            );
          }
          mappings.push({
            listenPort,
            targetHost,
            targetPort,
            listenHost: options.host,
            serve: options.serve,
            funnel: options.funnel,
          });
        }

        if (mappings.length === 0) {
          throw new Error(
            "RELAY_SPEC_REQUIRED: specify --listen & --target, or --map <port:port>, or --file <config.json>",
          );
        }

        const actions: string[] = [];

        const multiRelay = await startMultiRelay(mappings, {
          onConnection: (mapping, addr) => {
            if (!program.opts<{ json?: boolean }>().json) {
              console.error(
                `[relay :${mapping.listenPort}] Connection from ${addr} -> forwarding to ${mapping.targetHost}:${mapping.targetPort}`,
              );
            }
          },
          onError: (mapping, err) => {
            if (!program.opts<{ json?: boolean }>().json) {
              console.error(
                `[relay :${mapping.listenPort}] Error: ${err.message}`,
              );
            }
          },
        });

        for (const m of mappings) {
          actions.push(
            `TCP relay listening on ${m.listenHost ?? options.host ?? "0.0.0.0"}:${m.listenPort} -> ${m.targetHost}:${m.targetPort}`,
          );
        }

        // Tailscale Serve / Funnel integration
        const wantsServe = options.serve || mappings.some((m) => m.serve);
        const wantsFunnel = options.funnel || mappings.some((m) => m.funnel);

        if (wantsServe || wantsFunnel) {
          if (process.platform === "win32") {
            const daemon = await inspectDaemon();
            if (!daemon.running) {
              throw new Error(
                `TAILSCALED_NOT_RUNNING: Tailscale daemon (service) is not running.\n` +
                  `  Start it with: net start Tailscale\n` +
                  `  Or open Tailscale GUI app and sign in.\n` +
                  `  Without the daemon, "tailscale serve/funnel" cannot work.`,
              );
            }
          }
          const local = new TailscaleLocal(await findTailscale());
          for (const m of mappings) {
            try {
              if (options.serve || m.serve) {
                await local.serve([
                  "--bg",
                  "--yes",
                  `--tcp=${m.listenPort}`,
                  `tcp://127.0.0.1:${m.listenPort}`,
                ]);
                actions.push(
                  `configured Tailscale Serve on TCP port ${m.listenPort}`,
                );
              }
              if (options.funnel || m.funnel) {
                await local.funnel([
                  "--bg",
                  `--tcp=${m.listenPort}`,
                  `tcp://127.0.0.1:${m.listenPort}`,
                ]);
                actions.push(
                  `configured Tailscale Funnel on TCP port ${m.listenPort}`,
                );
              }
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              if (
                process.platform === "win32" &&
                msg.includes("ProtectedPrefix\\Administrators")
              ) {
                throw new Error(
                  `TAILSCALE_SERVE_REQUIRES_ADMIN: configuring "tailscale serve/funnel" on Windows requires an elevated terminal (Run as Administrator).\n` +
                    `  Option 1 (Recommended): remove "--serve" and "--funnel". All TCP relays listening on 0.0.0.0 are ALREADY accessible directly over Tailscale (e.g. 100.x.y.z:${m.listenPort}) without needing tailscale serve.\n` +
                    `  Option 2: open PowerShell / Command Prompt with "Run as Administrator" and re-run with --serve/--funnel.`,
                );
              }
              if (
                process.platform === "win32" &&
                msg.includes("cannot find the file specified")
              ) {
                throw new Error(
                  `TAILSCALED_NOT_RUNNING: "tailscale serve/funnel" failed because the Tailscale daemon (service) cannot be reached.\n` +
                    `  1. Ensure Tailscale is installed and the service is running: net start Tailscale\n` +
                    `  2. Sign in via the Tailscale GUI app\n` +
                    `  3. Re-run this command\n` +
                    `  Or remove "--serve"/"--funnel" — TCP relays on 0.0.0.0 are ALREADY accessible over Tailscale directly.`,
                );
              }
              throw err;
            }
          }
        }

        emit(
          "relay",
          {
            status: "running",
            count: mappings.length,
            mappings,
            tailscaleServe: Boolean(wantsServe),
            tailscaleFunnel: Boolean(wantsFunnel),
          },
          [],
          actions,
          [],
          start,
        );

        // Keep process alive for relay unless interrupted
        await new Promise<void>((resolve) => {
          process.on("SIGINT", () => {
            void multiRelay.close().then(() => resolve());
          });
          process.on("SIGTERM", () => {
            void multiRelay.close().then(() => resolve());
          });
        });
      } catch (error) {
        fail("relay", error, start);
      }
    },
  );

program
  .command("relay-mcp-postgres")
  .description(
    "Run TCP relays to PostgreSQL and serve a nexql-mcp HTTP MCP endpoint exposing all databases on the relayed instance (agent-driven connection via setup_connection)",
  )
  .option("-l, --listen <port>", "local listen port (e.g. 15433)")
  .option(
    "-t, --target <host:port>",
    "PostgreSQL target host:port (e.g. 100.x.y.z:5433 or other-host:5433)",
  )
  .option(
    "-m, --map <mapping...>",
    "repeatable port mappings, e.g. '15433:192.168.50.79:5433' (first mapping is the primary DB endpoint)",
  )
  .option(
    "-f, --file <configPath>",
    "path to JSON configuration file defining array of relay mappings",
  )
  .option(
    "--host <address>",
    "default listen host (default: 0.0.0.0)",
    "0.0.0.0",
  )
  .option(
    "--target-host <address>",
    "default target host when using simple listen:targetPort mappings",
    "127.0.0.1",
  )
  .option(
    "--mcp-port <port>",
    "HTTP MCP listen port for nexql-mcp (default: 8787)",
    "8787",
  )
  .option(
    "--mcp-bind <address>",
    "HTTP MCP bind address for nexql-mcp (default: 127.0.0.1; use 0.0.0.0 to expose over the tailnet)",
    "127.0.0.1",
  )
  .option(
    "--token <token>",
    "HTTP MCP bearer token (auto-generated when omitted; also reads NEXQL_MCP_HTTP_TOKEN)",
  )
  .option(
    "--user <user>",
    "PostgreSQL user for the primary endpoint (default: postgres)",
    "postgres",
  )
  .option(
    "--password <password>",
    "PostgreSQL password for the primary endpoint (default: $PGPASSWORD or $TS_PGPASSWORD; never printed)",
  )
  .option(
    "--database <database>",
    "default PostgreSQL database for the primary endpoint (default: postgres)",
    "postgres",
  )
  .option(
    "--db-retry-interval <ms>",
    "respawn retry interval for nexql-mcp while the PostgreSQL target is unreachable (default: 5000)",
    "5000",
  )
  .option(
    "--mcp-ready-timeout <ms>",
    "timeout for nexql-mcp to become ready in milliseconds (default: 30000)",
    "30000",
  )
  .option("--log <path>", "path to append nexql-mcp output logs")
  .option(
    "--primary-fallback",
    "allow falling back to another reachable mapped database if mapping[0] is unreachable",
  )
  .option(
    "--allow-partial",
    "allow running healthy relays even if some ports fail to bind (degraded mode)",
  )
  .option(
    "--connect-timeout <ms>",
    "TCP connection timeout to target in milliseconds (default: 5000)",
    "5000",
  )
  .option(
    "--serve",
    "also configure tailscale serve for all relay ports in the tailnet",
  )
  .option(
    "--funnel",
    "also configure tailscale funnel for all relay ports publicly (requires --serve)",
  )
  .option(
    "--apply-policy",
    "allow HuJSON-preserving tagOwners/nodeAttrs provisioning for funnel/serve (requires --serve or --funnel)",
  )
  .option(
    "--enable-https",
    "enable tailnet-wide HTTPS before configuring funnel (required for Funnel; only applied when --funnel is set)",
  )
  .option("--yes", "skip confirmation prompts for policy/HTTPS operations")
  .action(
    async (options: {
      listen?: string;
      target?: string;
      map?: string[];
      file?: string;
      host?: string;
      targetHost?: string;
      mcpPort?: string;
      mcpBind?: string;
      token?: string;
      user?: string;
      password?: string;
      database?: string;
      dbRetryInterval?: string;
      mcpReadyTimeout?: string;
      primaryFallback?: boolean;
      allowPartial?: boolean;
      connectTimeout?: string;
      log?: string;
      serve?: boolean;
      funnel?: boolean;
      applyPolicy?: boolean;
      enableHttps?: boolean;
      yes?: boolean;
    }) => {
      const start = performance.now();
      let multiRelay:
        { relays: unknown[]; close: () => Promise<void> } | undefined;
      let nexqlPid: number | undefined;
      try {
        const mappings: RelayMapping[] = [];

        if (options.file) {
          mappings.push(...loadRelayConfigFile(options.file));
        }
        if (options.map && options.map.length > 0) {
          for (const m of options.map) {
            mappings.push(
              parseRelayMapping(m, options.targetHost ?? "127.0.0.1"),
            );
          }
        }
        if (options.listen && options.target) {
          const listenPort = Number(options.listen);
          if (
            !Number.isFinite(listenPort) ||
            listenPort <= 0 ||
            listenPort > 65535
          ) {
            throw new Error(
              `RELAY_PORT_INVALID: --listen must be a valid port number (1-65535), got ${options.listen}`,
            );
          }
          const targetParts = options.target.split(":");
          if (targetParts.length !== 2) {
            throw new Error(
              `RELAY_TARGET_INVALID: --target must be format host:port, got ${options.target}`,
            );
          }
          const targetHost = targetParts[0]!.trim();
          const targetPort = Number(targetParts[1]!.trim());
          if (
            !targetHost ||
            !Number.isFinite(targetPort) ||
            targetPort <= 0 ||
            targetPort > 65535
          ) {
            throw new Error(
              `RELAY_TARGET_INVALID: invalid host or port in --target ${options.target}`,
            );
          }
          mappings.push({
            listenPort,
            targetHost,
            targetPort,
            listenHost: options.host,
            serve: options.serve,
            funnel: options.funnel,
          });
        }

        if (mappings.length === 0) {
          throw new Error(
            "RELAY_SPEC_REQUIRED: specify --listen & --target, or --map <port:port>, or --file <config.json>",
          );
        }

        const mcpPort = Number(options.mcpPort);
        if (!Number.isFinite(mcpPort) || mcpPort <= 0 || mcpPort > 65535) {
          throw new Error(
            `NEXQL_MCP_PORT_INVALID: --mcp-port must be a valid port number (1-65535), got ${options.mcpPort}`,
          );
        }
        const mcpBind = options.mcpBind?.trim() || "127.0.0.1";
        if (!/^[\w.*:\[\]-]+$/.test(mcpBind)) {
          throw new Error(
            `NEXQL_MCP_BIND_INVALID: --mcp-bind must be a valid IP/host, got ${options.mcpBind}`,
          );
        }
        const dbRetryInterval = Number(options.dbRetryInterval ?? 5_000);
        if (
          !Number.isFinite(dbRetryInterval) ||
          dbRetryInterval < 1_000 ||
          dbRetryInterval > 60_000
        ) {
          throw new Error(
            `NEXQL_MCP_RETRY_INVALID: --db-retry-interval must be between 1000 and 60000 ms, got ${options.dbRetryInterval}`,
          );
        }
        const mcpReadyTimeout = Number(options.mcpReadyTimeout);
        if (
          !Number.isFinite(mcpReadyTimeout) ||
          mcpReadyTimeout <= 0 ||
          mcpReadyTimeout > 120_000
        ) {
          throw new Error(
            `NEXQL_MCP_READY_TIMEOUT_INVALID: --mcp-ready-timeout must be a positive integer <= 120000, got ${options.mcpReadyTimeout}`,
          );
        }

        // MCP primary selection: mapping[0] is the configured default.
        // When --primary-fallback is enabled and mapping[0] is unreachable while
        // another relayed database is up, the first reachable mapping becomes
        // the primary so the MCP endpoint stays usable instead of respawning
        // nexql-mcp forever.
        let primaryIndex = 0;
        let primaryReason =
          "mapping[0] is the configured primary DB (default; use --primary-fallback to allow failover)";
        if (options.primaryFallback) {
          const primaryProbes = await Promise.all(
            mappings.map(async (m) => {
              try {
                await preflightTcpCheck({
                  host: m.targetHost,
                  port: m.targetPort,
                  timeoutMs: 3_000,
                });
                return true;
              } catch {
                return false;
              }
            }),
          );
          const reachable = primaryProbes
            .map((ok, i) => (ok ? i : -1))
            .filter((i) => i >= 0);
          primaryIndex =
            reachable.length === 0 || reachable[0] === 0 ? 0 : reachable[0]!;
          if (primaryIndex !== 0) {
            const fb = mappings[primaryIndex]!;
            primaryReason = `PRIMARY_FALLBACK: mapping[0] (${mappings[0]!.targetHost}:${mappings[0]!.targetPort}) unreachable; using first reachable mapping[${primaryIndex}] (${fb.targetHost}:${fb.targetPort}, database: ${fb.database ?? options.database ?? "postgres"}) as MCP primary`;
          } else {
            primaryReason =
              "mapping[0] is the configured primary (target reachable)";
          }
        }
        const primary = mappings[primaryIndex]!;
        const runner: NexqlMcpRunner = await resolveNexqlMcpRunner();

        // Console spam guard: identical relay errors are logged once per
        // change, connections once per throttle window per port, and
        // supervisor retries once per state change with a slow heartbeat.
        const lastErrorByPort = new Map<number, string>();
        const lastConnectionByPort = new Map<number, number>();
        const CONNECTION_LOG_INTERVAL_MS = 30_000;
        let lastRetryMessage = "";
        let retryCount = 0;
        const quietJson = (): boolean =>
          Boolean(program.opts<{ json?: boolean }>().json);

        const connectTimeoutMs = options.connectTimeout
          ? Number(options.connectTimeout)
          : 5_000;

        const resolvedMappings = mappings.map((m) => ({
          ...m,
          listenHost: m.listenHost ?? options.host ?? "0.0.0.0",
        }));

        multiRelay = await startMultiRelay(
          resolvedMappings,
          {
            onConnection: (mapping, addr) => {
              if (quietJson()) return;
              const now = Date.now();
              const last = lastConnectionByPort.get(mapping.listenPort) ?? 0;
              if (now - last >= CONNECTION_LOG_INTERVAL_MS) {
                lastConnectionByPort.set(mapping.listenPort, now);
                console.error(
                  `[relay-mcp-postgres :${mapping.listenPort}] Connection from ${addr} -> forwarding to ${mapping.targetHost}:${mapping.targetPort}`,
                );
              }
            },
            onError: (mapping, err) => {
              if (quietJson()) return;
              if (lastErrorByPort.get(mapping.listenPort) === err.message)
                return;
              lastErrorByPort.set(mapping.listenPort, err.message);
              console.error(
                `[relay-mcp-postgres :${mapping.listenPort}] Error: ${err.message}`,
              );
            },
          },
          {
            allowPartial: Boolean(options.allowPartial),
            connectTimeoutMs,
          },
        );

        // Every successfully bound relay listener must be up before we hand the endpoint to
        // nexql-mcp; the DB target itself is allowed to be down.
        for (const r of (multiRelay as MultiRelayInstance).relays) {
          await preflightTcpCheck({
            host: "127.0.0.1",
            port: r.mapping.listenPort,
            timeoutMs: 5_000,
          });
        }

        const token =
          options.token ?? process.env.NEXQL_MCP_HTTP_TOKEN ?? randomToken();
        const password =
          primary.password ??
          options.password ??
          process.env.PGPASSWORD ??
          process.env.TS_PGPASSWORD ??
          "";
        const user = primary.user ?? options.user;
        const database = primary.database ?? options.database;
        const connectionString = `postgres://${user}:${encodeURIComponent(password)}@127.0.0.1:${primary.listenPort}/${database}`;
        const logPath = options.log ?? join(cacheBinDir(), "nexql-mcp.log");

        const wantsServe = options.serve || mappings.some((m) => m.serve);
        const wantsFunnel = options.funnel || mappings.some((m) => m.funnel);
        let serveSkipWarning: string | undefined;

        if (wantsServe || wantsFunnel) {
          // Auto-provision funnel readiness (HTTPS + node attribute) when requested
          if (wantsFunnel && (options.applyPolicy || options.enableHttps)) {
            const config = resolveConfig(configEnv());
            const credentialEnv = resolvedCredentialEnv();
            if (options.enableHttps) {
              const api = new TailscaleApiClient(
                config,
                process.env,
                credentialEnv,
              );
              await api.enableHttps();
            }
            if (options.applyPolicy) {
              const { tags: deploymentTags } = resolveTags(config);
              await ensureDeployTags(config, deploymentTags, {
                yes: Boolean(options.yes),
                ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
              });
              await ensureFunnelReadiness(config, deploymentTags, {
                yes: Boolean(options.yes),
                applyPolicy: true,
                ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
              });

              // Ensure the current node advertises the required tags.
              // On Windows, `tailscale up --advertise-tags` requires --reset
              // which logs the user out. Instead, check the API first: if
              // the node already has the tags via API, skip the local
              // `tailscale up` — the tailscale daemon will sync eventually.
              const local = new TailscaleLocal(await findTailscale());
              try {
                const status = await local.status<{
                  Self?: { Tags?: string[]; ID?: string };
                }>();
                const currentTags = status.Self?.Tags ?? [];
                const missingTags = deploymentTags.filter(
                  (t) => !currentTags.includes(t),
                );
                if (missingTags.length) {
                  // Tags missing locally — verify via API before attempting
                  // `tailscale up` which can be disruptive on Windows.
                  const apiTagsOk = await (async () => {
                    try {
                      const api = new TailscaleApiClient(
                        config,
                        process.env,
                        credentialEnv,
                      );
                      const nodeId = status.Self?.ID;
                      if (!nodeId) return false;
                      const device = await api.getDevice(nodeId);
                      return missingTags.every((t) =>
                        (device.tags ?? []).includes(t),
                      );
                    } catch {
                      return false;
                    }
                  })();
                  if (apiTagsOk) {
                    // Tags exist via API — wait for local daemon to sync
                    await new Promise((r) => setTimeout(r, 2000));
                  }
                  // If tags truly missing via API, skip — tailscale funnel
                  // will produce a descriptive error telling the user what to do
                }
              } catch {
                // best-effort: if tags check fails, tailscale funnel will
                // produce a descriptive error anyway
              }
            }
          }

          const local = new TailscaleLocal(await findTailscale());
          if (process.platform === "win32") {
            const daemon = await inspectDaemon();
            if (!daemon.running) {
              throw new Error(
                `TAILSCALED_NOT_RUNNING: Tailscale daemon (service) is not running.\n` +
                  `  Start it with: net start Tailscale\n` +
                  `  Or open Tailscale GUI app and sign in.\n` +
                  `  Without the daemon, "tailscale serve/funnel" cannot work.`,
              );
            }
          }
          // Logged-out tailnet: serve/funnel cannot be configured, but the
          // TCP relays and the MCP endpoint do not need Tailscale at all —
          // degrade (skip serve/funnel) instead of killing the whole command.
          let tailnetAuthUrl: string | undefined;
          try {
            const st = await local.status<{
              BackendState?: string;
              AuthURL?: string;
            }>();
            if (st.BackendState === "NeedsLogin") {
              tailnetAuthUrl = st.AuthURL ?? "run `tailscale login`";
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (/logged out|log in at/i.test(msg)) {
              tailnetAuthUrl = "run `tailscale login`";
            }
          }
          if (tailnetAuthUrl) {
            serveSkipWarning =
              `TAILNET_LOGGED_OUT: node is logged out of the tailnet — skipped tailscale serve/funnel. ` +
              `TCP relays and the MCP endpoint stay up (reachable locally and via direct IP). ` +
              `Log back in at: ${tailnetAuthUrl}`;
            if (!quietJson()) {
              console.error(`[relay-mcp-postgres] ${serveSkipWarning}`);
            }
          }
          if (!tailnetAuthUrl) {
            for (const m of mappings) {
              try {
                if (options.serve || m.serve) {
                  await local.serve([
                    "--bg",
                    "--yes",
                    `--tcp=${m.listenPort}`,
                    `tcp://127.0.0.1:${m.listenPort}`,
                  ]);
                }
                if (options.funnel || m.funnel) {
                  await local.funnel([
                    "--bg",
                    `--tcp=${m.listenPort}`,
                    `tcp://127.0.0.1:${m.listenPort}`,
                  ]);
                }
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (
                  process.platform === "win32" &&
                  msg.includes("ProtectedPrefix\\Administrators")
                ) {
                  throw new Error(
                    `TAILSCALE_SERVE_REQUIRES_ADMIN: configuring "tailscale serve/funnel" on Windows requires an elevated terminal (Run as Administrator).\n` +
                      `  Option 1 (Recommended): remove "--serve" and "--funnel". When using "--mcp-bind 0.0.0.0" and "--host 0.0.0.0", all TCP relays and the MCP endpoint are ALREADY accessible directly over Tailscale (e.g. http://100.x.y.z:${mcpPort}/mcp and 100.x.y.z:${m.listenPort}) without needing tailscale serve.\n` +
                      `  Option 2: open PowerShell / Command Prompt with "Run as Administrator" and re-run with --serve/--funnel.`,
                  );
                }
                if (
                  process.platform === "win32" &&
                  msg.includes("cannot find the file specified")
                ) {
                  throw new Error(
                    `TAILSCALED_NOT_RUNNING: "tailscale serve/funnel" failed because the Tailscale daemon (service) cannot be reached.\n` +
                      `  1. Ensure Tailscale is installed and the service is running: net start Tailscale\n` +
                      `  2. Sign in via the Tailscale GUI app\n` +
                      `  3. Re-run this command\n` +
                      `  Or remove "--serve"/"--funnel" — TCP relays on 0.0.0.0 are ALREADY accessible over Tailscale directly.`,
                  );
                }
                if (
                  msg.includes("allowed nodes") ||
                  msg.includes("does not include the one you are using")
                ) {
                  throw new Error(
                    `FUNNEL_NODE_NOT_ALLOWED: tailscale funnel rejected the request because this node is not in the policy's allowed list.\n` +
                      `  Possible causes:\n` +
                      `  1. The node does not have the required tag — ensure --apply-policy was used and check "tailscale status" for Tags\n` +
                      `  2. The tagOwners/funnel nodeAttrs were not provisioned — re-run with --apply-policy --yes\n` +
                      `  3. Manual fix: visit the URL shown in the error above, or run "tailscale set --advertise-tags=<tag>"`,
                  );
                }
                throw err;
              }
            }

            // Expose MCP HTTP endpoint over tailnet HTTPS when --serve/--funnel
            // is used and MCP is bound to a non-loopback address.
            if (wantsServe && mcpBind !== "127.0.0.1" && mcpBind !== "::1") {
              try {
                if (wantsFunnel) {
                  await local.funnel([
                    "--bg",
                    "--yes",
                    "--https=443",
                    `http://127.0.0.1:${mcpPort}`,
                  ]);
                } else {
                  await local.serve([
                    "--bg",
                    "--yes",
                    "--https=443",
                    `http://127.0.0.1:${mcpPort}`,
                  ]);
                }
              } catch {
                // best-effort: MCP endpoint remains accessible over plain
                // HTTP on the tailnet IP even without HTTPS serve
              }
            }
          }
        }

        // Supervisor: keep nexql-mcp alive so the MCP HTTP endpoint is
        // available even before the PostgreSQL machine has booted. nexql-mcp
        // exits immediately when the database is unreachable, so we respawn it
        // until the DB accepts connections, and respawn again if it dies
        // mid-flight (e.g. the DB machine shuts down and comes back).
        const retryInterval = dbRetryInterval;
        let stopping = false;

        // Collect profile names from mappings for --profile flag
        const profileNames = resolvedMappings.map(
          (m) => m.name ?? `relay-${m.listenPort}`,
        );

        // Re-register profiles before EVERY spawn: nexql-mcp rotates the
        // global config.toml → config.toml.bak-<ts> and rewrites it on each
        // start, which can drop profiles (observed: profiles vanish one by
        // one until the file disappears). Registering once at startup left
        // the supervisor in a permanent "profile not found" respawn loop.
        const registerProfiles = (): Promise<void> =>
          registerRelayProfiles({
            runner,
            mappings: resolvedMappings.map((m) => ({
              listenPort: m.listenPort,
              targetHost: m.targetHost,
              targetPort: m.targetPort,
              ...(m.user !== undefined ? { user: m.user } : {}),
              ...(m.password !== undefined ? { password: m.password } : {}),
              ...(m.database !== undefined ? { database: m.database } : {}),
              ...(m.name !== undefined ? { name: m.name } : {}),
              ...(m.accessMode !== undefined
                ? { accessMode: m.accessMode }
                : {}),
            })),
          });

        const trySpawn = async (): Promise<
          { pid: number; waitForExit: Promise<void> } | undefined
        > => {
          try {
            await registerProfiles();
            const started = await startNexqlMcpHttp({
              runner,
              connectionString,
              httpPort: mcpPort,
              bind: mcpBind,
              token,
              logPath,
              readyTimeoutMs: mcpReadyTimeout,
              profiles: profileNames,
            });
            nexqlPid = started.pid;
            retryCount = 0;
            lastRetryMessage = "";
            if (!quietJson()) {
              console.error(
                `[relay-mcp-postgres] nexql-mcp HTTP MCP ready on http://127.0.0.1:${mcpPort}/mcp (pid ${started.pid})`,
              );
            }
            return { pid: started.pid, waitForExit: started.waitForExit };
          } catch (error) {
            if (!quietJson()) {
              retryCount += 1;
              const msg =
                error instanceof Error ? error.message : String(error);
              if (msg !== lastRetryMessage || retryCount % 10 === 0) {
                lastRetryMessage = msg;
                console.error(
                  `[relay-mcp-postgres] database not reachable yet; retrying nexql-mcp in ${retryInterval}ms (${msg})`,
                );
              }
            }
            nexqlPid = undefined;
            return undefined;
          }
        };

        const supervisor = (async (): Promise<void> => {
          let spawned = await trySpawn();
          while (!stopping) {
            if (spawned === undefined) {
              await sleep(retryInterval);
              spawned = await trySpawn();
              continue;
            }
            try {
              await spawned.waitForExit;
            } catch {
              // waitForExit always resolves; a throw here is unexpected, so
              // simply respawn on the next iteration.
            }
            if (stopping) break;
            if (!quietJson()) {
              console.error(
                "[relay-mcp-postgres] nexql-mcp exited (database went down); respawning",
              );
            }
            nexqlPid = undefined;
            spawned = undefined;
          }
        })();

        const sanitizedMappings = mappings.map((m) => ({
          ...m,
          ...(m.password !== undefined
            ? { password: maskSecret(m.password) }
            : {}),
        }));

        emit(
          "relay-mcp-postgres",
          {
            status: "running",
            relayCount: mappings.length,
            mappings: sanitizedMappings,
            primaryMappingIndex: primaryIndex,
            primaryReason,
            endpoints: mappings.map((m) => ({
              listen: `${m.listenHost ?? options.host ?? "0.0.0.0"}:${m.listenPort}`,
              target: `${m.targetHost}:${m.targetPort}`,
              ...(m.user !== undefined ? { user: m.user } : {}),
              ...(m.password !== undefined
                ? { password: maskSecret(m.password) }
                : {}),
              ...(m.database !== undefined ? { database: m.database } : {}),
            })),
            primaryDatabase: database,
            degraded: Boolean((multiRelay as MultiRelayInstance).degraded),
            ...((multiRelay as MultiRelayInstance).failed
              ? { failedEndpoints: (multiRelay as MultiRelayInstance).failed }
              : {}),
            mcpHttpUrl: `http://${mcpBind === "0.0.0.0" ? "0.0.0.0" : mcpBind}:${mcpPort}/mcp`,
            mcpToken: maskToken(token),
            connectionString: maskConnString(connectionString),
            nexqlMcpPid: nexqlPid ?? null,
            runnerVersion: runner.version,
            tailscaleServe: Boolean(wantsServe),
            tailscaleFunnel: Boolean(wantsFunnel),
          },
          [
            "setup_connection can only target ports already relayed via --map/--file/--listen; the agent cannot open new relay ports at runtime",
            "MCP server stays up even when the PostgreSQL machine is down; it reconnects automatically once the database accepts connections (supervisor retry)",
            ...(primaryIndex !== 0
              ? [
                  `PRIMARY_FALLBACK: ${mappings[0]!.targetHost}:${mappings[0]!.targetPort} unreachable; MCP primary is mapping[${primaryIndex}] (${primary.targetHost}:${primary.targetPort})`,
                ]
              : []),
            ...(serveSkipWarning ? [serveSkipWarning] : []),
          ],
          [
            `TCP relay listening on ${primary.listenHost ?? options.host ?? "0.0.0.0"}:${primary.listenPort} -> ${primary.targetHost}:${primary.targetPort}`,
            `nexql-mcp HTTP MCP listening on http://127.0.0.1:${mcpPort}/mcp (token masked)`,
          ],
          [],
          start,
        );

        // Integrated OAuth wrapper for Claude.ai/ChatGPT web — confidential client (id+secret required)
        const oauthPort = Number(process.env.OAUTH_PORT ?? 3000);
        const publicUrl =
          process.env.PUBLIC_URL ??
          `https://${process.env.TS_HOSTNAME ?? "mcp-postgres"}.${process.env.TS_TAILNET && process.env.TS_TAILNET !== "-" ? process.env.TS_TAILNET : "tailadac87.ts.net"}`;
        let oauthServer: { close: () => void } | undefined;
        try {
          const { startOAuthWrapper } = await import("./oauth-wrapper.js");
          oauthServer = startOAuthWrapper({
            mcpTarget: `http://127.0.0.1:${mcpPort}`,
            token,
            port: oauthPort,
            publicUrl,
            ...(process.env.OAUTH_CLIENT_ID
              ? { clientId: process.env.OAUTH_CLIENT_ID }
              : {}),
            ...(process.env.OAUTH_CLIENT_SECRET
              ? { clientSecret: process.env.OAUTH_CLIENT_SECRET }
              : {}),
          });
          if (!quietJson())
            console.error(
              `[relay-mcp-postgres] oauth-wrapper listening on 0.0.0.0:${oauthPort} → http://127.0.0.1:${mcpPort} (public ${publicUrl})`,
            );
          if (wantsServe) {
            try {
              const local2 = new TailscaleLocal(await findTailscale());
              if (wantsFunnel) {
                await local2.funnel([
                  "--bg",
                  "--yes",
                  "--https=443",
                  `http://127.0.0.1:${oauthPort}`,
                ]);
              } else {
                await local2.serve([
                  "--bg",
                  "--yes",
                  "--https=443",
                  `http://127.0.0.1:${oauthPort}`,
                ]);
              }
              if (!quietJson())
                console.error(
                  `[relay-mcp-postgres] tailscale ${wantsFunnel ? "funnel" : "serve"} reconfigured to oauth-wrapper :${oauthPort}`,
                );
            } catch {}
          }
        } catch {}

        await new Promise<void>((resolve) => {
          const shutdown = (): void => {
            stopping = true;
            try {
              oauthServer?.close();
            } catch {}
            void Promise.all([
              multiRelay?.close().catch(() => {}),
              (async () => {
                if (nexqlPid !== undefined) {
                  const res = await stopNexqlMcpHttp();
                  void res;
                }
              })(),
              supervisor,
            ]).then(() => resolve());
          };
          process.on("SIGINT", shutdown);
          process.on("SIGTERM", shutdown);
        });
      } catch (error) {
        await multiRelay?.close().catch(() => {});
        if (nexqlPid !== undefined) {
          const res = await stopNexqlMcpHttp();
          void res;
        }
        fail("relay-mcp-postgres", error, start);
      }
    },
  );

program
  .command("dns")
  .description("Read tailnet DNS settings; optionally enable MagicDNS")
  .option("--enable-magicdns")
  .option("--dry-run")
  .option("--yes")
  .action(
    async (options: {
      enableMagicdns?: boolean;
      dryRun?: boolean;
      yes?: boolean;
    }) => {
      const start = performance.now();
      try {
        const api = new TailscaleApiClient(
          resolveConfig(configEnv()),
          process.env,
          resolvedCredentialEnv(),
        );
        if (options.enableMagicdns) {
          const approved = await confirm(
            "Enable MagicDNS on the tailnet?",
            Boolean(options.yes),
          );
          if (!approved)
            throw new Error(
              "DNS_MAGICDNS_CONFIRMATION_REQUIRED: pass --yes to enable MagicDNS",
            );
          if (options.dryRun) {
            emit(
              "dns",
              { magicDNSEnabled: true, dryRun: true },
              [],
              [],
              [],
              start,
            );
            return;
          }
          await api.enableMagicDns();
          emit(
            "dns",
            { magicDNSEnabled: true },
            [],
            ["enable MagicDNS"],
            [],
            start,
          );
          return;
        }
        emit("dns", await api.getDns(), [], [], [], start);
      } catch (error) {
        fail("dns", error, start);
      }
    },
  );

program
  .command("policy")
  .description("Diff, validate and guarded-sync a HuJSON policy file")
  .option("--file <path>")
  .option("--sync")
  .option("--dry-run")
  .option("--yes")
  .option(
    "--backup-dir <path>",
    "directory for policy backups (default: ./.tailscale-cli)",
  )
  .action(
    async (options: {
      file?: string;
      sync?: boolean;
      dryRun?: boolean;
      yes?: boolean;
      backupDir?: string;
    }) => {
      const start = performance.now();
      try {
        const file = options.file ?? policyFromEnv();
        if (!file)
          throw new Error(
            "POLICY_FILE_REQUIRED: pass --file or TS_POLICY_FILE",
          );
        const credentialEnv = resolvedCredentialEnv();
        const result = await policySync(resolveConfig(configEnv()), file, {
          dryRun: Boolean(options.dryRun ?? !options.sync),
          yes: Boolean(options.yes),
          ...(options.backupDir ? { backupDir: options.backupDir } : {}),
          ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
        });
        emit(
          "policy",
          result,
          [],
          result.written ? ["policy write", "policy backup"] : [],
          [],
          start,
        );
      } catch (error) {
        fail("policy", error, start);
      }
    },
  );

program
  .command("cleanup")
  .description("Find and safely remove matching offline devices")
  .option("--dry-run")
  .option("--yes")
  .action(async (options: { dryRun?: boolean; yes?: boolean }) => {
    const start = performance.now();
    try {
      const credentialEnv = resolvedCredentialEnv();
      const result = await cleanup(resolveConfig(configEnv()), {
        dryRun: Boolean(options.dryRun),
        yes: Boolean(options.yes),
        ...(credentialEnv ? { credentialEnvName: credentialEnv } : {}),
      });
      emit(
        "cleanup",
        result,
        result.candidates.length ? ["destructive: exact candidates only"] : [],
        result.deleted.map((id) => `delete device ${id}`),
        [],
        start,
      );
    } catch (error) {
      fail("cleanup", error, start);
    }
  });

function serviceLog(
  level: "INFO" | "OK" | "WARN" | "ERROR",
  message: string,
): void {
  if (program.opts<{ json?: boolean }>().json) return;
  const ts = new Date().toISOString();
  const colors: Record<string, string> = {
    INFO: "",
    OK: "\x1b[32m",
    WARN: "\x1b[33m",
    ERROR: "\x1b[31m",
  };
  const useColor = Boolean(process.stderr.isTTY);
  const lvl = useColor ? `${colors[level]}${level}\x1b[0m` : level;
  console.error(`[tailsacle-service] ${ts}  ${lvl}  ${message}`);
}

const serviceCmd = program
  .command("service")
  .description(
    "Install, manage and remove a relay/script as a background service (systemd on Linux, Windows SCM or Task Scheduler)",
  );

serviceCmd
  .command("init")
  .description("Generate a sample JSON/JSONC service config file")
  .option("--name <name>", "service name", "tailsacle-relay")
  .option("--out <file>", "output file path", ".tailsacle-service.jsonc")
  .action(async (options: { name: string; out: string }) => {
    const start = performance.now();
    try {
      if (!/^[a-zA-Z0-9-]+$/.test(options.name)) {
        throw new Error(
          `SERVICE_NAME_INVALID: only alphanumeric and hyphens allowed, got "${options.name}"`,
        );
      }
      const content = generateSampleConfig(options.name);
      writeFileSync(options.out, content, "utf8");
      emit(
        "service init",
        { file: resolvePath(options.out), name: options.name },
        [],
        ["write sample service config file"],
        [],
        start,
      );
    } catch (error) {
      fail("service init", error, start);
    }
  });

function managerForService(name: string): ServiceManager {
  const entry = registryFind(name);
  if (
    entry?.platform === "win32" &&
    entry.unitPath?.startsWith("tailsacle-cli\\")
  ) {
    return getSchedulerManager();
  }
  return getServiceManager();
}

serviceCmd
  .command("install")
  .description(
    "Install and enable the service from a config file (systemd system/user unit, Windows SCM, or Task Scheduler)",
  )
  .requiredOption(
    "--file <config>",
    "path to the service config file (JSON/JSONC)",
  )
  .option(
    "--user",
    "install as a systemd user service (Linux only, no sudo required)",
  )
  .option(
    "--scheduler",
    "install via Windows Task Scheduler instead of SCM (no admin required)",
  )
  .option("--yes", "skip confirmation")
  .action(
    async (options: {
      file: string;
      user?: boolean;
      scheduler?: boolean;
      yes?: boolean;
    }) => {
      const start = performance.now();
      try {
        const config = loadServiceConfig(options.file);
        if (
          !(await confirm(
            `Install service "${config.name}"?`,
            Boolean(options.yes),
          ))
        ) {
          throw new Error(
            "SERVICE_CONFIRMATION_REQUIRED: pass --yes to install without confirmation",
          );
        }
        if (options.user && options.scheduler) {
          throw new Error(
            "SERVICE_OPTIONS_CONFLICT: --user and --scheduler cannot be combined",
          );
        }
        // Windows SCM always requires Admin. Check before attempting install so
        // the error message is actionable rather than a cryptic "access denied".
        if (
          process.platform === "win32" &&
          !options.scheduler &&
          !isAdminUser()
        ) {
          throw new Error(
            "SERVICE_REQUIRES_ADMIN: installing a Windows SCM service requires an elevated terminal.\n" +
              '  Option 1: re-run this command in a terminal opened with "Run as Administrator".\n' +
              "  Option 2: use --scheduler to register via Task Scheduler (no admin required, but only starts after login):\n" +
              `    tailsacle-cli service install --file ${options.file} --scheduler --yes`,
          );
        }
        serviceLog("INFO", `Installing service "${config.name}"...`);
        const manager = options.scheduler
          ? getSchedulerManager()
          : getServiceManager();
        const result = await manager.install(config, {
          user: options.user,
          scheduler: options.scheduler,
        });

        serviceLog("OK", `Service "${config.name}" installed and started`);
        const warnings: string[] = [];
        if (result.portsListening?.length) {
          if (process.platform === "linux") {
            let listening = listeningPortsLinux();
            for (
              let attempt = 0;
              attempt < 20 &&
              !result.portsListening.every((p) => listening.includes(p));
              attempt += 1
            ) {
              await new Promise((r) => setTimeout(r, 500));
              listening = listeningPortsLinux();
            }
            for (const port of result.portsListening) {
              if (listening.includes(port)) {
                serviceLog("OK", `Port ${port}: LISTEN`);
              } else {
                serviceLog(
                  "WARN",
                  `Port ${port}: not listening yet (service may still be starting)`,
                );
                warnings.push(`PORT_NOT_LISTENING: ${port}`);
              }
            }
          } else {
            for (const port of result.portsListening) {
              serviceLog("INFO", `Port ${port}: registered (check via status)`);
            }
          }
        }
        const envEntries = Object.entries(maskEnv(config.env));
        if (envEntries.length) {
          serviceLog(
            "INFO",
            `Env: ${envEntries.map(([k, v]) => `${k}=${v}`).join(", ")}`,
          );
        }
        serviceLog(
          "OK",
          `Status: ${result.status}${result.pid ? ` — PID ${result.pid}` : ""}`,
        );
        if (process.platform === "linux" && result.scope === "user") {
          const user = resolveUserName(config.user);
          if (!lingerEnabled(user)) {
            warnings.push(
              `SERVICE_LINGER_DISABLED: run "loginctl enable-linger ${user}" so the user service auto-starts on boot`,
            );
            serviceLog(
              "WARN",
              `loginctl linger not enabled — service won't auto-start on boot (loginctl enable-linger ${user})`,
            );
          }
        }
        emit(
          "service install",
          {
            installed: true,
            name: result.name,
            platform: result.platform,
            scope: result.scope,
            unitPath: result.unitPath,
            status: result.status,
            pid: result.pid,
            portsListening: result.portsListening,
          },
          warnings,
          [
            `install ${result.scope === "user" ? "user" : "system"} service ${result.name}`,
            ...(result.unitPath ? [`unit file: ${result.unitPath}`] : []),
          ],
          result.platform === "linux" && result.scope === "system"
            ? ["root/sudo for systemd system unit"]
            : [],
          start,
        );
      } catch (error) {
        fail("service install", error, start);
      }
    },
  );

serviceCmd
  .command("uninstall")
  .description("Uninstall and remove the service (stops it first)")
  .requiredOption("--name <name>", "service name")
  .option("--yes", "skip confirmation")
  .action(async (options: { name: string; yes?: boolean }) => {
    const start = performance.now();
    try {
      if (
        !(await confirm(
          `Uninstall service "${options.name}"?`,
          Boolean(options.yes),
        ))
      ) {
        throw new Error(
          "SERVICE_CONFIRMATION_REQUIRED: pass --yes to uninstall without confirmation",
        );
      }
      const manager = managerForService(options.name);
      await manager.uninstall(options.name);
      serviceLog("OK", `Service "${options.name}" uninstalled`);
      emit(
        "service uninstall",
        { uninstalled: true, name: options.name },
        [],
        [`uninstall service ${options.name}`],
        [],
        start,
      );
    } catch (error) {
      fail("service uninstall", error, start);
    }
  });

serviceCmd
  .command("status")
  .description("Show service status (running/stopped/error, PID, uptime)")
  .requiredOption("--name <name>", "service name")
  .action(async (options: { name: string }) => {
    const start = performance.now();
    try {
      const manager = managerForService(options.name);
      const status = await manager.status(options.name);
      serviceLog(
        "INFO",
        `Service "${options.name}": ${status.status}${
          status.pid ? ` (PID ${status.pid})` : ""
        }${status.uptimeSeconds !== undefined ? `, uptime ${status.uptimeSeconds}s` : ""}${
          status.restartCount ? `, restarts ${status.restartCount}` : ""
        }`,
      );
      emit("service status", status, [], [], [], start);
    } catch (error) {
      fail("service status", error, start);
    }
  });

serviceCmd
  .command("logs")
  .description(
    "Show service logs (journald on Linux, WinSW log files on Windows)",
  )
  .requiredOption("--name <name>", "service name")
  .option("--lines <n>", "number of log lines to show", "50")
  .option("--follow", "stream logs in real time")
  .action(
    async (options: { name: string; lines: string; follow?: boolean }) => {
      const start = performance.now();
      try {
        const manager = managerForService(options.name);
        const lines = Number(options.lines);
        if (!Number.isFinite(lines) || lines < 1) {
          throw new Error(
            `SERVICE_LOG_LINES_INVALID: --lines must be a positive integer, got ${options.lines}`,
          );
        }
        await manager.logs(options.name, {
          lines: Math.floor(lines),
          follow: Boolean(options.follow),
        });
        if (program.opts<{ json?: boolean }>().json) {
          emit(
            "service logs",
            { name: options.name, followed: Boolean(options.follow) },
            [],
            [],
            [],
            start,
          );
        }
      } catch (error) {
        fail("service logs", error, start);
      }
    },
  );

serviceCmd
  .command("start")
  .description("Start the service")
  .requiredOption("--name <name>", "service name")
  .action(async (options: { name: string }) => {
    const start = performance.now();
    try {
      const manager = managerForService(options.name);
      await manager.start(options.name);
      const status = await manager.status(options.name);
      serviceLog("OK", `Service "${options.name}" started`);
      emit(
        "service start",
        status,
        [],
        [`start service ${options.name}`],
        [],
        start,
      );
    } catch (error) {
      fail("service start", error, start);
    }
  });

serviceCmd
  .command("stop")
  .description("Stop the service")
  .requiredOption("--name <name>", "service name")
  .action(async (options: { name: string }) => {
    const start = performance.now();
    try {
      const manager = managerForService(options.name);
      await manager.stop(options.name);
      const status = await manager.status(options.name);
      serviceLog("OK", `Service "${options.name}" stopped`);
      emit(
        "service stop",
        status,
        [],
        [`stop service ${options.name}`],
        [],
        start,
      );
    } catch (error) {
      fail("service stop", error, start);
    }
  });

serviceCmd
  .command("restart")
  .description("Restart the service")
  .requiredOption("--name <name>", "service name")
  .action(async (options: { name: string }) => {
    const start = performance.now();
    try {
      const manager = managerForService(options.name);
      await manager.restart(options.name);
      const status = await manager.status(options.name);
      serviceLog("OK", `Service "${options.name}" restarted`);
      emit(
        "service restart",
        status,
        [],
        [`restart service ${options.name}`],
        [],
        start,
      );
    } catch (error) {
      fail("service restart", error, start);
    }
  });

serviceCmd
  .command("list")
  .description("List services installed by tailsacle-cli")
  .action(async () => {
    const start = performance.now();
    try {
      const manager = getServiceManager();
      const entries = await manager.list();
      if (!program.opts<{ json?: boolean }>().json) {
        for (const entry of entries) {
          serviceLog(
            "INFO",
            `${entry.name} (${entry.platform}/${entry.scope}) — ${entry.status}${
              entry.pid ? ` (PID ${entry.pid})` : ""
            }${entry.installedAt ? `, installed ${entry.installedAt}` : ""}`,
          );
        }
      }
      emit("service list", entries, [], [], [], start);
    } catch (error) {
      fail("service list", error, start);
    }
  });

program
  .command("agent-manifest")
  .description("Print the machine-readable agent contract")
  .action(async () => {
    const start = performance.now();
    const opts = program.opts<{ json?: boolean }>();
    if (opts.json) emit("agent-manifest", manifest, [], [], [], start);
    else console.log(JSON.stringify(manifest, null, 2));
  });

program
  .command("daemon")
  .description("Inspect or stop the local tailscaled daemon")
  .argument(
    "<action>",
    "status (report the daemon and any userspace instance this tool started) or stop (stop only a userspace tailscaled tracked in the daemon pidfile)",
  )
  .action(async (action: string) => {
    const start = performance.now();
    try {
      if (action === "stop") {
        const result = await stopUserspaceDaemon();
        emit(
          "daemon",
          { action, ...result },
          result.stopped ? [] : [result.message],
          result.stopped ? ["stop tracked userspace tailscaled"] : [],
          [],
          start,
        );
        return;
      }
      if (action !== "status")
        throw new Error(
          `DAEMON_ACTION_INVALID: expected "status" or "stop", got "${action}"`,
        );
      const status = await daemonStatus();
      emit(
        "daemon",
        {
          action,
          running: status.running,
          tracked: status.tracked,
          trackedAlive: status.trackedAlive,
        },
        status.warnings,
        status.actions,
        [],
        start,
      );
    } catch (error) {
      fail("daemon", error, start);
    }
  });

const rawArgs = process.argv.slice(2);

void (async () => {
  if (rawArgs.includes("--update-bin")) {
    program.parseOptions(rawArgs);
    const handled = await handleGlobalFlags();
    if (handled) return;
  }
  if (rawArgs.length === 0 && process.stdin.isTTY && process.stdout.isTTY) {
    const { interactiveMenu } = await import("./menu.js");
    const argv = await interactiveMenu();
    if (!argv.length) return;
    console.log(
      `\n# Equivalent non-interactive command:\n$ tailsacle-cli ${argv.join(" ")}\n`,
    );
    const { spawn } = await import("node:child_process");
    const invoked = process.argv[1] ?? "";
    const child = spawn(process.execPath, [invoked, ...argv], {
      stdio: "inherit",
      env: process.env,
    });
    await new Promise<void>((resolve, reject) => {
      child.on("error", reject);
      child.on("exit", (code) => {
        if (code && code !== 0 && !process.exitCode) process.exitCode = code;
        resolve();
      });
    });
    return;
  }
  await program.parseAsync(process.argv).catch(() => {
    if (!process.exitCode) process.exitCode = 1;
  });
})();
