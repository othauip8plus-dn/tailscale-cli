import os from "node:os";
import type {
  Device,
  DeploymentResult,
  Exposure,
  ResolvedConfig,
} from "./types.js";
import { ApiError, TailscaleApiClient } from "./api.js";
import type { CreatedAuthKey } from "./api.js";
import { tailscaleVersion, TailscaleLocal } from "./tailscale.js";
import { cleanup as runCleanup } from "./cleanup.js";
import {
  ensureDeployTags,
  ensureFunnelAccess,
  ensureHttpsEnabled,
  ensureSshAccess,
  funnelCovered,
  sshCovered,
} from "./policy.js";
import { ensureDaemon } from "./daemon.js";

export const DOCUMENTED_AUTH_KEY_CEILING_SECONDS = 90 * 24 * 60 * 60;
const KEY_EXPIRY_MAX_WARNING =
  "KEY_EXPIRY_MAX: max maps to the documented 90-day auth-key ceiling; no API endpoint reports the real server maximum, so a larger value is never claimed (this is the auth-key expiry used to join, not the node key-expiry policy)";
const KEY_EXPIRY_UNLIMITED_WARNING =
  "KEY_EXPIRY_UNLIMITED: unlimited is capped at the documented 90-day auth-key ceiling; Tailscale does not offer truly unlimited auth keys";

export function resolveKeyExpiry(configured: string): number {
  const raw = (configured ?? "").trim().toLowerCase();
  if (raw === "" || raw === "max" || raw === "unlimited")
    return DOCUMENTED_AUTH_KEY_CEILING_SECONDS;
  const seconds = Number(raw);
  if (!Number.isFinite(seconds) || seconds <= 0)
    throw new Error(
      'KEY_EXPIRY_INVALID: TS_KEY_EXPIRY must be "max" or a positive number of seconds',
    );
  return seconds;
}

export function resolveKeyExpiryPlan(
  configured: string,
  source: string,
): { seconds: number; warnings: string[] } {
  const raw = (configured ?? "").trim().toLowerCase();
  const seconds = resolveKeyExpiry(configured);
  const warnings: string[] = [];
  if (raw === "" || raw === "max") {
    if (source === "default") warnings.push(KEY_EXPIRY_MAX_WARNING);
  } else if (raw === "unlimited") {
    warnings.push(KEY_EXPIRY_UNLIMITED_WARNING);
  } else if (seconds > DOCUMENTED_AUTH_KEY_CEILING_SECONDS) {
    warnings.push(
      `KEY_EXPIRY_CLAMPED: ${seconds}s exceeds the documented 90-day auth-key ceiling; using the ceiling instead`,
    );
    return { seconds: DOCUMENTED_AUTH_KEY_CEILING_SECONDS, warnings };
  }
  return { seconds, warnings };
}

const FUNNEL_ATTR_ERROR = /funnel.*(not available|node attribute not set)/i;

/**
 * Runs `funnel`, tolerating the window where the funnel node attribute was
 * just provisioned but policy has not propagated yet: once a propagation
 * failure is seen, every remaining attempt is retried and only the final
 * error is classified — a propagation error becomes FUNNEL_ATTR_REQUIRED,
 * anything else is re-raised verbatim.
 */
export async function runFunnelWithAttrRetry(
  runFunnel: () => Promise<void>,
  options: { retryDelayMs?: number; attempts?: number } = {},
): Promise<void> {
  const delayMs = options.retryDelayMs ?? 3000;
  const attempts = options.attempts ?? 4;
  try {
    await runFunnel();
    return;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!FUNNEL_ATTR_ERROR.test(message)) throw error;
    let lastError: unknown = error;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        await runFunnel();
        return;
      } catch (retryError) {
        lastError = retryError;
      }
    }
    const retryMessage =
      lastError instanceof Error ? lastError.message : String(lastError);
    if (FUNNEL_ATTR_ERROR.test(retryMessage))
      throw new Error(
        `FUNNEL_ATTR_REQUIRED: the funnel node attribute was provisioned but is not effective yet; Tailscale policy propagation can take ~30s. ${retryMessage}`,
        { cause: lastError },
      );
    throw lastError;
  }
}

function truthy(value: string | undefined): boolean {
  return (
    value !== undefined &&
    ["1", "true", "yes", "on"].includes(value.toLowerCase())
  );
}

function normalizeTag(tag: string): string {
  return tag.startsWith("tag:") ? tag : `tag:${tag}`;
}

export function parseExposure(value: string): Exposure {
  const eq = value.trim().split("=", 2);
  const [publicPartRaw, rawPath] = (eq[0] ?? "").split("#", 2);
  const publicPart = publicPartRaw ?? "";
  const path = rawPath
    ? rawPath.startsWith("/")
      ? rawPath
      : `/${rawPath}`
    : undefined;
  let publicPort: number | undefined;
  if (/^\d+$/.test(publicPart.trim())) {
    publicPort = Number(publicPart.trim());
    if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535)
      throw new Error(`EXPOSE_INVALID_PUBLIC_PORT: ${publicPart.trim()}`);
  }
  const normalized = (eq.length === 2 ? (eq[1] ?? "") : publicPart).trim();
  let target: string;

  if (/^\d+$/.test(normalized)) target = `http://127.0.0.1:${normalized}`;
  else if (/^(?:https?|tcp|https\+insecure):\/\//.test(normalized))
    target = normalized;
  else if (/^(?:localhost|127\.0\.0\.1)(?::\d+)?$/.test(normalized))
    target = `http://${normalized}`;
  else throw new Error(`EXPOSE_INVALID_TARGET: ${value.trim()}`);

  const portMatch = target.match(/:(\d+)(?:\/|$)/);
  return {
    target,
    public: false,
    ...(path ? { path } : {}),
    ...(publicPort !== undefined
      ? { https: publicPort }
      : portMatch
        ? { https: Number(portMatch[1]) }
        : {}),
  };
}

export function resolveExposures(
  values: string[],
  publicFunnel: boolean,
): Exposure[] {
  return values
    .filter(Boolean)
    .map((value) => ({ ...parseExposure(value), public: publicFunnel }));
}

function buildUpArgs(config: ResolvedConfig): string[] {
  const args = [
    `--hostname=${config.hostname}`,
    `--accept-dns=${config.acceptDns}`,
    `--accept-routes=${config.acceptRoutes}`,
  ];
  if (process.platform !== "win32")
    args.push(config.ssh ? "--ssh" : "--ssh=false");
  if (config.profile === "exit-node") args.push("--advertise-exit-node");
  if (config.profile === "subnet-router" && process.env.TS_ADVERTISE_ROUTES)
    args.push(`--advertise-routes=${process.env.TS_ADVERTISE_ROUTES}`);
  if (config.profile === "funnel-app") args.push("--advertise-connector");
  if (process.platform === "win32" && truthy(process.env.TS_UNATTENDED))
    args.push("--unattended");
  return args;
}

function deviceFromStatus(status: unknown): Device | Record<string, unknown> {
  if (!status || typeof status !== "object") return { status };
  const data = status as Record<string, unknown>;
  const self = data.Self;
  if (!self || typeof self !== "object") return data;
  const item = self as Record<string, unknown>;
  const device: Device = { id: String(item.ID ?? ""), online: true };
  if (typeof item.DNSName === "string") {
    device.name = item.DNSName;
    device.dnsName = item.DNSName;
  }
  if (typeof item.HostName === "string") device.hostname = item.HostName;
  if (typeof item.OS === "string") device.os = item.OS;
  return device;
}

function redactEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const copy = { ...env };
  delete copy.TS_API_KEY;
  delete copy.TS_ACCESS_TOKEN;
  delete copy.TS_CLIENT_SECRET;
  delete copy.TS_OAUTH_CLIENT_SECRET;
  delete copy.TS_AUTH_KEY;
  return copy;
}

function isTagProvisionError(error: unknown): boolean {
  if (!(error instanceof ApiError) || error.status !== 400) return false;
  const message = error.message.toLowerCase();
  return (
    message.includes("tags") &&
    (message.includes("invalid") ||
      message.includes("not permitted") ||
      message.includes("must have tags"))
  );
}

export function currentUsername(): string {
  try {
    return (
      os.userInfo().username ||
      process.env.USER ||
      process.env.USERNAME ||
      "user"
    );
  } catch {
    return process.env.USER || process.env.USERNAME || "user";
  }
}

export function resolveTags(config: ResolvedConfig): {
  tags: string[];
  autoTagged: boolean;
} {
  let autoTagged = false;
  let tags = [...config.tags];
  if (!tags.length) {
    const repo =
      process.env.GITHUB_REPOSITORY ||
      process.env.GITLAB_PROJECT_PATH ||
      process.env.CI_PROJECT_PATH;
    const base =
      process.env.TS_TAG_BASE?.trim() ||
      (repo
        ? repo
            .replace(/\//g, "-")
            .replace(/[^a-z0-9-]+/gi, "-")
            .toLowerCase()
        : config.profile === "ci"
          ? "tailsacle-cli"
          : config.hostname);
    const tag = `tag:${base.replace(/^-+|-+$/g, "") || "tailsacle-cli"}`;
    tags = [tag];
    autoTagged = true;
  }

  if (config.ssh) {
    const user = currentUsername();
    const userSlug =
      user
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "user";
    const sshTag = `tag:sshwhoami-${userSlug}`;
    if (!tags.includes(sshTag)) {
      tags.push(sshTag);
    }
  }

  return { tags, autoTagged };
}

export async function ensureFunnelReadiness(
  config: ResolvedConfig,
  tags: string[],
  options: {
    yes: boolean;
    applyPolicy?: boolean;
    credentialEnvName?: string;
    backupDir?: string;
  },
): Promise<string[]> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  let covered: boolean | undefined;
  try {
    const policy = await api.getPolicy();
    covered = funnelCovered(policy.json, tags);
  } catch (error) {
    if (error instanceof ApiError && [401, 403].includes(error.status))
      return [
        "FUNNEL_ATTR_UNVERIFIABLE: no policy read scope, so the funnel node attribute could not be verified before running funnel (if funnel fails, re-run with --apply-policy)",
      ];
    throw error;
  }
  if (covered) return [];
  if (!options.applyPolicy)
    throw new Error(
      "FUNNEL_ATTR_REQUIRED: the funnel node attribute is missing for the deployment tags; re-run with --apply-policy to auto-add it on the tailnet (before running funnel)",
    );
  const warnings: string[] = [
    "SIDE_EFFECT_PLAN: auto-adding the funnel node attribute before running funnel",
  ];
  const provisioned = await ensureFunnelAccess(config, tags, {
    yes: options.yes,
    ...(options.credentialEnvName
      ? { credentialEnvName: options.credentialEnvName }
      : {}),
    ...(options.backupDir ? { backupDir: options.backupDir } : {}),
  });
  warnings.push(...provisioned.warnings);
  return warnings;
}

export async function ensureSshReadiness(
  config: ResolvedConfig,
  tags: string[],
  options: {
    yes: boolean;
    applyPolicy?: boolean;
    credentialEnvName?: string;
    backupDir?: string;
  },
): Promise<string[]> {
  if (!config.ssh) return [];
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  if (!api.hasCredentials()) return [];
  let covered: boolean | undefined;
  try {
    const policy = await api.getPolicy();
    covered = sshCovered(policy.json, tags);
  } catch (error) {
    if (error instanceof ApiError && [401, 403].includes(error.status))
      return [
        "SSH_POLICY_UNVERIFIABLE: no policy read scope, so SSH policy rule could not be verified",
      ];
    throw error;
  }
  if (covered) return [];
  if (options.yes && options.applyPolicy) {
    const warnings: string[] = [
      "SIDE_EFFECT_PLAN: auto-adding SSH policy accept rule before deployment completes",
    ];
    const provisioned = await ensureSshAccess(config, tags, {
      yes: options.yes,
      ...(options.credentialEnvName
        ? { credentialEnvName: options.credentialEnvName }
        : {}),
      ...(options.backupDir ? { backupDir: options.backupDir } : {}),
    });
    warnings.push(...provisioned.warnings);
    return warnings;
  }
  return [
    `SSH_POLICY_WARNING: tailnet policy does not explicitly permit SSH access for ${tags.join(", ") || "nodes"}; pass --apply-policy --yes to auto-provision an SSH policy accept rule`,
  ];
}

export async function deploy(
  config: ResolvedConfig,
  options: {
    dryRun: boolean;
    yes: boolean;
    expose: string[];
    funnel: boolean;
    applyPolicy?: boolean;
    enableHttps?: boolean;
    cleanup?: boolean;
    bin?: string;
    credentialEnvName?: string;
    tagOwner?: string[];
    backupDir?: string;
  },
): Promise<DeploymentResult> {
  const warnings: string[] = [];
  const binary = await tailscaleVersion(options.bin);
  const daemon = await ensureDaemon(
    config.stateDir ? { stateDir: config.stateDir } : undefined,
  );
  if (!daemon.running) warnings.push(...daemon.warnings);
  else if (daemon.actions.length)
    warnings.push(`DAEMON_STARTED: ${daemon.actions.join("; ")}`);
  const exposures = resolveExposures(options.expose, options.funnel);
  const expiryPlan = resolveKeyExpiryPlan(
    config.keyExpiry,
    config.source.keyExpiry ?? "",
  );
  const expirySeconds = expiryPlan.seconds;
  warnings.push(...expiryPlan.warnings);
  if (process.platform === "win32" && config.ssh === true)
    warnings.push(
      "SSH_DISABLED_ON_WINDOWS: the Tailscale SSH server is not supported on Windows; --ssh was ignored",
    );
  const { tags: deploymentTags, autoTagged } = resolveTags(config);
  if (autoTagged)
    warnings.push(
      `AUTO_TAG: no TS_TAGS configured; using deterministic tag ${deploymentTags[0]} (override with TS_TAGS)`,
    );
  const tags = deploymentTags.map(normalizeTag);
  if (options.dryRun) {
    return {
      binary,
      device: { dryRun: true, config },
      authKeySource: process.env.TS_AUTH_KEY ? "provided" : "created",
      exposures,
      warnings,
      source: config.source,
    };
  }

  const local = new TailscaleLocal(binary.path);
  let authKey = process.env.TS_AUTH_KEY?.trim();
  let authKeySource: "provided" | "created" = "provided";

  if (authKey && !authKey.startsWith("tskey-auth-"))
    throw new Error(
      "AUTH_KEY_FORMAT_INVALID: TS_AUTH_KEY must start with tskey-auth-",
    );

  if (!authKey) {
    const api = new TailscaleApiClient(
      config,
      process.env,
      options.credentialEnvName,
    );
    if (!api.hasCredentials())
      throw new Error(
        "AUTH_KEY_NOT_CONFIGURED: set TS_AUTH_KEY or configure TS_API_KEY/TS_ACCESS_TOKEN/OAuth client credentials",
      );
    const createKey = (): Promise<CreatedAuthKey> =>
      api.createAuthKey({
        reusable: config.reusable,
        ephemeral: config.ephemeral,
        preauthorized: config.preauthorized,
        tags,
        expirySeconds,
      });
    try {
      const created = await createKey();
      authKey = created.key;
      authKeySource = "created";
    } catch (error) {
      if (!isTagProvisionError(error) || !options.yes || !options.applyPolicy)
        throw error;
      warnings.push(
        "SIDE_EFFECT_PLAN: auto-provisioning tagOwners for the requested tags before retrying the auth-key request",
      );
      try {
        const provisioned = await ensureDeployTags(config, tags, {
          yes: true,
          ...(options.tagOwner?.length ? { owner: options.tagOwner } : {}),
          ...(options.credentialEnvName
            ? { credentialEnvName: options.credentialEnvName }
            : {}),
          ...(options.backupDir ? { backupDir: options.backupDir } : {}),
        });
        warnings.push(...provisioned.warnings);
      } catch (provisionError) {
        throw provisionError;
      }
      const created = await createKey();
      authKey = created.key;
      authKeySource = "created";
    }
  }

  const args = buildUpArgs(config);
  if (authKeySource === "provided" && tags.length)
    args.push(`--advertise-tags=${tags.join(",")}`);
  args.push(`--auth-key=${authKey}`);
  await local.up(args, redactEnv(process.env));

  const status = await local.status<Record<string, unknown>>();
  const state =
    typeof status.BackendState === "string" ? status.BackendState : undefined;
  if (state !== "Running")
    throw new Error(
      `TAILSCALE_NOT_RUNNING: BackendState=${state ?? "unknown"}`,
    );

  if (exposures.length && options.yes && options.enableHttps) {
    const https = await ensureHttpsEnabled(config, {
      yes: true,
      ...(options.credentialEnvName
        ? { credentialEnvName: options.credentialEnvName }
        : {}),
    });
    warnings.push(...https.warnings);
  }

  if (exposures.some((exposure) => exposure.public)) {
    warnings.push(
      ...(await ensureFunnelReadiness(config, tags, {
        yes: options.yes,
        ...(options.applyPolicy !== undefined
          ? { applyPolicy: options.applyPolicy }
          : {}),
        ...(options.credentialEnvName
          ? { credentialEnvName: options.credentialEnvName }
          : {}),
        ...(options.backupDir ? { backupDir: options.backupDir } : {}),
      })),
    );
  }

  if (config.ssh) {
    warnings.push(
      ...(await ensureSshReadiness(config, tags, {
        yes: options.yes,
        ...(options.applyPolicy !== undefined
          ? { applyPolicy: options.applyPolicy }
          : {}),
        ...(options.credentialEnvName
          ? { credentialEnvName: options.credentialEnvName }
          : {}),
        ...(options.backupDir ? { backupDir: options.backupDir } : {}),
      })),
    );
  }

  const runExposure = async (exposure: Exposure): Promise<void> => {
    const cmdArgs = ["--bg"];
    if (exposure.path) cmdArgs.push(`--set-path=${exposure.path}`);
    if (exposure.https) {
      if (exposure.public && ![443, 8443, 10000].includes(exposure.https))
        throw new Error(
          "FUNNEL_PORT_UNSUPPORTED: Funnel allows 443, 8443, or 10000",
        );
      cmdArgs.push(`--https=${exposure.https}`);
    }
    if (!exposure.public) {
      await local.serve([...cmdArgs, exposure.target]);
      return;
    }
    await runFunnelWithAttrRetry(() =>
      local.funnel([...cmdArgs, exposure.target]),
    );
  };

  for (const exposure of exposures) await runExposure(exposure);

  const device = deviceFromStatus(
    await local.status<Record<string, unknown>>(),
  );

  const cleanupResult = await (async (): Promise<
    DeploymentResult["cleanup"]
  > => {
    if (!options.cleanup || options.dryRun) return undefined;
    if (
      process.env.TS_NO_CLEANUP === "true" ||
      process.env.TS_NO_CLEANUP === "1"
    )
      return undefined;
    if (config.profile !== "ci" && config.profile !== "container")
      warnings.push(
        "CLEANUP_EXPLICIT: --cleanup was passed, so offline-device pruning runs on this profile (auto-cleanup otherwise only defaults to CI/container)",
      );
    try {
      const result = await runCleanup(config, {
        dryRun: false,
        yes: true,
        ...(options.credentialEnvName
          ? { credentialEnvName: options.credentialEnvName }
          : {}),
      });
      return {
        candidates: result.candidates.map((d) => d.id),
        deleted: result.deleted,
      };
    } catch {
      warnings.push(
        "CLEANUP_SKIPPED: no device cleanup permission; deploy succeeded without pruning offline devices",
      );
      return { candidates: [], deleted: [], skipped: true };
    }
  })();

  return {
    binary,
    device,
    authKeySource,
    exposures,
    warnings,
    source: config.source,
    ...(cleanupResult ? { cleanup: cleanupResult } : {}),
  };
}
