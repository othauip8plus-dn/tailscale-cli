import { TailscaleApiClient } from "./api.js";
import type { CleanupCandidate, Device, ResolvedConfig } from "./types.js";
import { confirm } from "./interactive.js";

function normalized(value: string | undefined): string {
  return (value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function isOffline(device: Device, afterSeconds: number): boolean {
  if (device.online === true) return false;
  if (!device.lastSeen) return false;
  const seen = Date.parse(device.lastSeen);
  return Number.isFinite(seen) && Date.now() - seen >= afterSeconds * 1000;
}

function protectedDevice(device: Device): boolean {
  const protectedNames = (process.env.TS_PROTECTED_DEVICES ?? "")
    .split(",")
    .map((v) => normalized(v.trim()))
    .filter(Boolean);
  const values = [
    normalized(device.id),
    normalized(device.name),
    normalized(device.hostname),
    normalized(device.dnsName),
  ];
  return protectedNames.some((name) => values.includes(name));
}

export function matchReason(
  device: Device,
  config: ResolvedConfig,
): string | undefined {
  const wantedHostname = normalized(config.hostname);
  const hostExact =
    (device.hostname ?? "").toLowerCase().replace(/\.$/, "") ===
    config.hostname.toLowerCase();
  const dnsLabel = (device.dnsName ?? "").toLowerCase().replace(/\.$/, "");
  const dnsExact =
    dnsLabel === config.hostname.toLowerCase() ||
    dnsLabel.startsWith(`${config.hostname.toLowerCase()}.`);
  const nameExact = normalized(device.name) === wantedHostname;
  const hostnameMatch = hostExact || dnsExact || nameExact;
  if (!hostnameMatch) return undefined;
  const tags = new Set(
    (device.tags ?? []).map((tag) => tag.replace(/^tag:/, "").toLowerCase()),
  );
  const wantedTags = config.tags.map((tag) =>
    tag.replace(/^tag:/, "").toLowerCase(),
  );
  const tagMatch =
    wantedTags.length === 0 || wantedTags.every((tag) => tags.has(tag));
  if (!tagMatch) return undefined;
  return wantedTags.length
    ? `hostname ${config.hostname} (exact) + tags ${wantedTags.join(", ")}`
    : `hostname ${config.hostname} (exact, no tag constraint)`;
}

export interface CleanupResult {
  candidates: CleanupCandidate[];
  deleted: string[];
}

/**
 * Thrown when some devices were deleted and others failed. Carries the exact
 * set of IDs already removed so callers can report it truthfully instead of
 * collapsing a partial run into `deleted: []`.
 */
export class CleanupPartialFailureError extends Error {
  readonly candidates: CleanupCandidate[];
  readonly deleted: string[];
  readonly failed: Array<{ id: string; error: string }>;

  constructor(result: {
    candidates: CleanupCandidate[];
    deleted: string[];
    failed: Array<{ id: string; error: string }>;
  }) {
    super(
      `CLEANUP_PARTIAL_FAILURE: ${result.deleted.length} of ${result.candidates.length} offline devices were deleted, ${result.failed.length} failed: ${result.failed
        .map((f) => `${f.id}: ${f.error}`)
        .join("; ")}`,
    );
    this.name = "CleanupPartialFailureError";
    this.candidates = result.candidates;
    this.deleted = result.deleted;
    this.failed = result.failed;
  }
}

export async function cleanup(
  config: ResolvedConfig,
  options: { dryRun: boolean; yes: boolean; credentialEnvName?: string },
): Promise<CleanupResult> {
  const api = new TailscaleApiClient(
    config,
    process.env,
    options.credentialEnvName,
  );
  const devices = await api.listDevices();
  const candidates: CleanupCandidate[] = [];
  for (const device of devices) {
    if (!isOffline(device, config.cleanupAfter)) continue;
    if (protectedDevice(device)) continue;
    const match = matchReason(device, config);
    if (!match) continue;
    const seen = device.lastSeen ? Date.parse(device.lastSeen) : Number.NaN;
    candidates.push({
      id: device.id,
      ...(device.hostname ? { hostname: device.hostname } : {}),
      ...(device.name ? { name: device.name } : {}),
      ...(device.dnsName ? { dnsName: device.dnsName } : {}),
      ...(device.tags ? { tags: device.tags } : {}),
      ...(device.lastSeen ? { lastSeen: device.lastSeen } : {}),
      offlineSinceSeconds: Number.isFinite(seen)
        ? Math.round((Date.now() - seen) / 1000)
        : 0,
      match,
    });
  }
  if (options.dryRun || candidates.length === 0)
    return { candidates, deleted: [] };

  const summary = candidates
    .map(
      (candidate) =>
        `${candidate.id} ${candidate.name ?? candidate.hostname ?? ""} (${candidate.match})`,
    )
    .join("\n");
  const approved = await confirm(
    `Delete these offline devices?\n${summary}`,
    options.yes,
  );
  if (!approved)
    throw new Error(
      "CLEANUP_CONFIRMATION_REQUIRED: use --yes in CI or confirm in a TTY",
    );

  const deleted: string[] = [];
  const failed: Array<{ id: string; error: string }> = [];
  for (const candidate of candidates) {
    try {
      await api.deleteDevice(candidate.id);
      deleted.push(candidate.id);
    } catch (error) {
      // Record the failure and keep going: losing the IDs of devices that
      // were already permanently deleted would make the envelope lie about
      // what happened to the tailnet.
      failed.push({
        id: candidate.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  if (failed.length)
    throw new CleanupPartialFailureError({ candidates, deleted, failed });
  return { candidates, deleted };
}
