import type {
  Device,
  DnsSettings,
  PolicyDocument,
  ResolvedConfig,
} from "./types.js";
import { parseHuJson } from "./hujson.js";
import { sleep } from "./utils.js";

const API_BASE = "https://api.tailscale.com/api/v2";
const OAUTH_TOKEN_URL = `${API_BASE}/oauth/token`;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(message: string, status: number, code = "TAILSCALE_API_ERROR") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryable = status === 408 || status === 429 || status >= 500;
  }
}

export function sanitizeServerText(text: string): string {
  return text
    .replace(/tskey-[A-Za-z0-9._-]{4,}/g, "tskey-***")
    .replace(/(bearer|basic)\s+[A-Za-z0-9._:-]{8,}/gi, "$1 ***");
}

type TokenSource = "bearer" | "basic" | "oauth";

interface AuthState {
  source: TokenSource;
  token?: string;
  clientId?: string;
  clientSecret?: string;
  formatError?: string;
}

function parseTrustCredential(value: string): { clientId: string } | undefined {
  const match = value.match(/^tskey-client-(.+)-(.+)$/);
  if (!match?.[1] || !match[2]) return undefined;
  return { clientId: match[1] };
}

interface OAuthTokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
}

export interface AuthKeyCreateOptions {
  reusable: boolean;
  ephemeral: boolean;
  preauthorized: boolean;
  tags: string[];
  expirySeconds?: number;
}

export interface CreatedAuthKey {
  key: string;
  id?: string;
  expires?: string;
  capabilities?: unknown;
}

export interface PolicySnapshot {
  content: string;
  etag?: string;
  json?: PolicyDocument;
}

function envFirst(...names: string[]): string | undefined {
  return names.map((name) => process.env[name]?.trim()).find(Boolean);
}

function encodePath(value: string): string {
  return encodeURIComponent(value);
}

export class TailscaleApiClient {
  private readonly config: ResolvedConfig;
  private readonly auth: AuthState;
  private oauthToken?: { value: string; expiresAt: number; key: string };

  constructor(
    config: ResolvedConfig,
    env: NodeJS.ProcessEnv = process.env,
    credentialEnvName?: string,
  ) {
    const accessToken = env.TS_ACCESS_TOKEN ?? env.TS_API_TOKEN;
    const apiKey = env.TS_API_KEY;
    const clientId = env.TS_OAUTH_CLIENT_ID ?? env.TS_CLIENT_ID;
    const clientSecret = env.TS_OAUTH_CLIENT_SECRET;
    const trustCredential = credentialEnvName
      ? env[credentialEnvName]?.trim()
      : env.TS_CLIENT_SECRET?.trim();
    this.config = config;

    if (accessToken) this.auth = { source: "bearer", token: accessToken };
    else if (apiKey) this.auth = { source: "basic", token: apiKey };
    else if (trustCredential) {
      if (trustCredential.startsWith("tskey-client-")) {
        const parsed = parseTrustCredential(trustCredential);
        this.auth = parsed
          ? {
              source: "oauth",
              clientId: parsed.clientId,
              clientSecret: trustCredential,
            }
          : {
              source: "oauth",
              formatError:
                "CREDENTIAL_FORMAT_UNSUPPORTED: TS_CLIENT_SECRET is not a valid tskey-client- trust credential",
            };
      } else if (clientId) {
        this.auth = {
          source: "oauth",
          clientId,
          clientSecret: trustCredential,
        };
      } else {
        this.auth = {
          source: "oauth",
          formatError:
            "CREDENTIAL_FORMAT_UNSUPPORTED: TS_CLIENT_SECRET must be a tskey-client- trust credential or require TS_CLIENT_ID",
        };
      }
    } else if (clientId && clientSecret)
      this.auth = { source: "oauth", clientId, clientSecret };
    else this.auth = { source: "bearer" };
  }

  hasCredentials(): boolean {
    return Boolean(
      this.auth.token || (this.auth.clientId && this.auth.clientSecret),
    );
  }

  private async oauthAccessToken(
    scopes: string[],
    tags: string[],
  ): Promise<string> {
    if (!this.auth.clientId || !this.auth.clientSecret)
      throw new ApiError(
        "Tailscale OAuth credentials are missing",
        401,
        "CREDENTIAL_NOT_FOUND",
      );
    const key = `${scopes.join(" ")}|${tags.join(",")}`;
    const now = Date.now();
    if (
      this.oauthToken &&
      this.oauthToken.key === key &&
      this.oauthToken.expiresAt > now + 30_000
    )
      return this.oauthToken.value;

    const body = new URLSearchParams({ grant_type: "client_credentials" });
    if (scopes.length) body.set("scope", scopes.join(" "));
    if (tags.length) body.set("tags", tags.join(" "));
    const basic = Buffer.from(
      `${this.auth.clientId}:${this.auth.clientSecret}`,
      "utf8",
    ).toString("base64");
    const response = await fetch(OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    const text = await response.text();
    if (!response.ok)
      throw new ApiError(
        `OAuth token request failed (${response.status}): ${sanitizeServerText(text).slice(0, 300)}`,
        response.status,
        "OAUTH_TOKEN_FAILED",
      );
    const data = JSON.parse(text) as OAuthTokenResponse;
    this.oauthToken = {
      value: data.access_token,
      expiresAt: now + Math.max(60, data.expires_in ?? 3600) * 1000,
      key,
    };
    return data.access_token;
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
    scopes: string[] = [],
    tags: string[] = [],
  ): Promise<{ data: T; headers: Headers; status: number }> {
    if (this.auth.formatError)
      throw new ApiError(
        this.auth.formatError,
        401,
        "CREDENTIAL_FORMAT_UNSUPPORTED",
      );
    const headers = new Headers(init.headers);
    headers.set("Accept", headers.get("Accept") ?? "application/json");
    if (init.body && !headers.has("Content-Type"))
      headers.set("Content-Type", "application/json");

    if (this.auth.source === "oauth") {
      headers.set(
        "Authorization",
        `Bearer ${await this.oauthAccessToken(scopes, tags)}`,
      );
    } else if (this.auth.token) {
      headers.set(
        "Authorization",
        this.auth.source === "basic"
          ? `Basic ${Buffer.from(`${this.auth.token}:`, "utf8").toString("base64")}`
          : `Bearer ${this.auth.token}`,
      );
    } else {
      throw new ApiError(
        "No Tailscale API credential configured",
        401,
        "CREDENTIAL_NOT_FOUND",
      );
    }

    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const response = await fetch(`${API_BASE}${path}`, {
          ...init,
          headers,
          signal: init.signal ?? AbortSignal.timeout(20_000),
        });
        const text = await response.text();
        if (response.ok) {
          if (!text)
            return {
              data: undefined as T,
              headers: response.headers,
              status: response.status,
            };
          const contentType = response.headers.get("content-type") ?? "";
          return {
            data: contentType.includes("json")
              ? parseHuJson<T>(text)
              : (text as T),
            headers: response.headers,
            status: response.status,
          };
        }
        let message = text;
        try {
          const parsed = JSON.parse(text) as { message?: string };
          if (parsed.message) message = parsed.message;
        } catch {
          // Keep the raw server text.
        }
        const error = new ApiError(
          sanitizeServerText(message.slice(0, 500)),
          response.status,
        );
        if (!error.retryable || attempt === 2) throw error;
        lastError = error;
        await sleep(250 * 2 ** attempt);
      } catch (error) {
        if (error instanceof ApiError) throw error;
        lastError = error;
        if (attempt === 2) throw error;
        await sleep(250 * 2 ** attempt);
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error("Tailscale API request failed");
  }

  private tailnet(): string {
    return this.config.tailnet && this.config.tailnet !== "-"
      ? encodePath(this.config.tailnet)
      : "-";
  }

  async listDevices(): Promise<Device[]> {
    const { data } = await this.request<{ devices?: Device[] }>(
      `/tailnet/${this.tailnet()}/devices`,
      {},
      ["devices:core:read"],
    );
    return data.devices ?? [];
  }

  async getDevice(id: string): Promise<Device> {
    const { data } = await this.request<Device>(
      `/device/${encodePath(id)}`,
      {},
      ["devices:core:read"],
    );
    return data;
  }

  async deleteDevice(id: string): Promise<void> {
    await this.request<void>(
      `/device/${encodePath(id)}`,
      { method: "DELETE" },
      ["devices:core"],
    );
  }

  async createAuthKey(options: AuthKeyCreateOptions): Promise<CreatedAuthKey> {
    const body = {
      capabilities: {
        devices: {
          create: {
            reusable: options.reusable,
            ephemeral: options.ephemeral,
            preauthorized: options.preauthorized,
            tags: options.tags,
          },
        },
      },
      ...(options.expirySeconds
        ? { expirySeconds: options.expirySeconds }
        : {}),
    };
    const { data } = await this.request<CreatedAuthKey>(
      `/tailnet/${this.tailnet()}/keys`,
      { method: "POST", body: JSON.stringify(body) },
      ["auth_keys"],
      options.tags,
    );
    if (!data.key)
      throw new ApiError(
        "Tailscale API did not return the auth key secret",
        502,
        "AUTH_KEY_NOT_RETURNED",
      );
    return data;
  }

  async getPolicy(): Promise<PolicySnapshot> {
    const { data, headers } = await this.request<PolicyDocument>(
      `/tailnet/${this.tailnet()}/acl`,
      { headers: { Accept: "application/json" } },
      ["policy_file:read"],
    );
    const etag = headers.get("etag") ?? undefined;
    return {
      content: JSON.stringify(data, null, 2),
      json: data,
      ...(etag ? { etag } : {}),
    };
  }

  async getPolicyHuJson(): Promise<{ content: string; etag?: string }> {
    const { data, headers } = await this.request<unknown>(
      `/tailnet/${this.tailnet()}/acl`,
      { headers: { Accept: "application/hujson" } },
      ["policy_file:read"],
    );
    const etag = headers.get("etag") ?? undefined;
    const content =
      typeof data === "string" ? data : JSON.stringify(data, null, 2);
    return { content, ...(etag ? { etag } : {}) };
  }

  async validatePolicy(policy: PolicyDocument): Promise<unknown> {
    const { data } = await this.request<unknown>(
      `/tailnet/${this.tailnet()}/acl/validate`,
      { method: "POST", body: JSON.stringify(policy) },
      ["policy_file:read"],
    );
    return data;
  }

  async validatePolicyText(content: string): Promise<unknown> {
    const { data } = await this.request<unknown>(
      `/tailnet/${this.tailnet()}/acl/validate`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/hujson",
          Accept: "application/json",
        },
        body: content,
      },
      ["policy_file:read"],
    );
    return data;
  }

  async updatePolicy(content: string, etag?: string): Promise<PolicySnapshot> {
    const headers: Record<string, string> = {
      "Content-Type": "application/hujson",
      Accept: "application/json",
    };
    if (etag) headers["If-Match"] = etag;
    const { data, headers: responseHeaders } =
      await this.request<PolicyDocument>(
        `/tailnet/${this.tailnet()}/acl`,
        { method: "POST", headers, body: content },
        ["policy_file"],
      );
    const responseEtag = responseHeaders.get("etag") ?? undefined;
    return {
      content: JSON.stringify(data, null, 2),
      json: data,
      ...(responseEtag ? { etag: responseEtag } : {}),
    };
  }

  async getDns(): Promise<DnsSettings> {
    const [nameservers, preferences, searchpaths] = await Promise.all([
      this.request<unknown>(`/tailnet/${this.tailnet()}/dns/nameservers`, {}, [
        "dns:read",
      ]),
      this.request<unknown>(`/tailnet/${this.tailnet()}/dns/preferences`, {}, [
        "dns:read",
      ]),
      this.request<unknown>(`/tailnet/${this.tailnet()}/dns/searchpaths`, {}, [
        "dns:read",
      ]),
    ]);
    return {
      nameservers: nameservers.data,
      preferences: preferences.data,
      searchpaths: searchpaths.data,
    };
  }

  async enableMagicDns(): Promise<void> {
    await this.request<unknown>(
      `/tailnet/${this.tailnet()}/dns/preferences`,
      { method: "POST", body: JSON.stringify({ magicDNS: true }) },
      ["dns"],
    );
    const { data } = await this.request<{ magicDNS?: boolean }>(
      `/tailnet/${this.tailnet()}/dns/preferences`,
      {},
      ["dns:read"],
    );
    if (data?.magicDNS !== true)
      throw new ApiError(
        "DNS_VERIFY_FAILED: MagicDNS is not reflected on the tailnet after the update",
        502,
        "DNS_VERIFY_FAILED",
      );
  }

  async getTailnetSettings(): Promise<{ httpsEnabled?: boolean }> {
    const { data } = await this.request<{ httpsEnabled?: boolean }>(
      `/tailnet/${this.tailnet()}/settings`,
      {},
      ["all:read"],
    );
    return data;
  }

  async enableHttps(): Promise<void> {
    await this.request<void>(
      `/tailnet/${this.tailnet()}/settings`,
      { method: "PATCH", body: JSON.stringify({ httpsEnabled: true }) },
      ["all"],
    );
  }
}

export function apiCredentialHint(
  env: NodeJS.ProcessEnv = process.env,
): string {
  const namedTrust = [
    "TS_TRUST_CREDENTIAL",
    "TS_API_TRUST",
    "TAILSCALE_TRUST_CREDENTIAL",
    "TAILSCALE_API_TRUST",
  ] as const;
  const selectedName = env.TS_CREDENTIAL_ENV?.trim();
  const trustValue = selectedName
    ? env[selectedName]?.trim()
    : env.TS_CLIENT_SECRET?.trim();
  const hasTrustCredential = Boolean(
    trustValue || namedTrust.some((name) => Boolean(env[name]?.trim())),
  );
  const hasCredential = Boolean(
    envFirst("TS_API_KEY", "TS_ACCESS_TOKEN", "TS_API_TOKEN") ||
    hasTrustCredential ||
    (env.TS_OAUTH_CLIENT_ID && env.TS_OAUTH_CLIENT_SECRET) ||
    (env.TS_CLIENT_ID && env.TS_CLIENT_SECRET),
  );
  return hasCredential ? "configured" : "missing";
}
