import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  sanitizeServerText,
  TailscaleApiClient,
} from "../src/api.js";
import type { ResolvedConfig } from "../src/types.js";

const testConfig: ResolvedConfig = {
  profile: "dev",
  tailnet: "-",
  hostname: "node-a",
  tags: [],
  ssh: true,
  keyExpiry: "max",
  preauthorized: true,
  reusable: false,
  ephemeral: false,
  acceptDns: true,
  acceptRoutes: false,
  cleanupAfter: 3600,
  source: {},
  warnings: [],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("ApiError retry semantics", () => {
  it("treats permission and scope failures as non-retryable", () => {
    expect(new ApiError("forbidden", 401).retryable).toBe(false);
    expect(new ApiError("forbidden", 403).retryable).toBe(false);
    expect(new ApiError("not found", 404).retryable).toBe(false);
    expect(new ApiError("conflict", 412).retryable).toBe(false);
  });

  it("treats transient responses as retryable", () => {
    expect(new ApiError("timeout", 408).retryable).toBe(true);
    expect(new ApiError("throttled", 429).retryable).toBe(true);
    expect(new ApiError("boom", 500).retryable).toBe(true);
    expect(new ApiError("gateway", 502).retryable).toBe(true);
  });
});

describe("sanitizeServerText", () => {
  it("masks trust credentials embedded in server error text", () => {
    const leaked =
      "tag mismatch: tskey-client-k522tBdJ5D21CNTRL-abcdefghijklmnopqrstuvwxyz123456 invalid";
    const sanitized = sanitizeServerText(leaked);
    expect(sanitized).not.toContain("k522tBdJ5D21CNTRL");
    expect(sanitized).toContain("tskey-***");
  });

  it("masks bearer/basic authorization material", () => {
    expect(
      sanitizeServerText("used Authorization: Bearer xoPd9s.-Secret8Token"),
    ).toContain("Bearer ***");
    expect(sanitizeServerText("basic c2VjcmV0aW5mbyE=")).toContain("basic ***");
  });

  it("leaves ordinary text untouched", () => {
    const normal = "policy has invalid tagOwners entry";
    expect(sanitizeServerText(normal)).toBe(normal);
  });
});

describe("MagicDNS preferences contract", () => {
  it("posts the camelCase magicDNS field and verifies read-after-write", async () => {
    const requests: { url: string; method: string; body?: string }[] = [];
    const fetcher = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = requests.length === 0 ? "POST" : "GET";
        const body = init?.body?.toString();
        requests.push({ url, method, ...(body !== undefined ? { body } : {}) });
        if (method === "POST") return jsonResponse({ magicDNS: true });
        return jsonResponse({ magicDNS: true });
      },
    );
    vi.stubGlobal("fetch", fetcher);

    const client = new TailscaleApiClient(testConfig, {
      TS_API_KEY: "tskey-api-key-value",
    });
    await client.enableMagicDns();

    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.url).toContain("/tailnet/-/dns/preferences");
    expect(requests[0]?.body).toBe('{"magicDNS":true}');
    expect(requests[1]?.method).toBe("GET");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("throws DNS_VERIFY_FAILED when the read-back does not reflect MagicDNS", async () => {
    let requestsSeen = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const method = requestsSeen++ === 0 ? "POST" : "GET";
        return method === "POST"
          ? jsonResponse({ magicDNS: true })
          : jsonResponse({ magicDNS: false });
      }),
    );

    const client = new TailscaleApiClient(testConfig, {
      TS_API_KEY: "tskey-api-key-value",
    });
    await expect(client.enableMagicDns()).rejects.toThrow("DNS_VERIFY_FAILED");
  });
});

describe("API credential precedence", () => {
  it("uses an explicit trust credential instead of a shadowing bearer token", async () => {
    const urls: string[] = [];
    const auths: (string | null)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        urls.push(url);
        auths.push(new Headers(init?.headers).get("authorization"));
        if (url.includes("/oauth/token"))
          return jsonResponse({
            access_token: "oauth-access-token",
            expires_in: 3600,
          });
        return jsonResponse({ acls: [] });
      }),
    );

    const client = new TailscaleApiClient(testConfig, {
      TS_CLIENT_SECRET:
        "tskey-client-k522tBdJ5D21CNTRL-abcdefghijklmnopqrstuvwxyz123456",
      TS_ACCESS_TOKEN: "tskey-access-token-should-not-win",
    });
    await client.getPolicy();

    expect(urls[0]).toContain("/oauth/token");
    expect(auths[0]).toMatch(/^Basic /);
  });
});

describe("HuJSON response handling", () => {
  it("preserves the raw HuJSON text (comments included) for policy writes", async () => {
    const raw = '{\n  // keep me\n  "tagOwners": {}\n}';
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(raw, {
            status: 200,
            headers: { "content-type": "application/hujson", etag: '"e1"' },
          }),
      ),
    );

    const client = new TailscaleApiClient(testConfig, {
      TS_API_KEY: "tskey-api-key-value",
    });
    const result = await client.getPolicyHuJson();
    expect(result.content).toBe(raw);
    expect(result.etag).toBe('"e1"');
  });
});
