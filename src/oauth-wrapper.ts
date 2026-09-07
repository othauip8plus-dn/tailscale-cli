import http from "node:http";
import { createHash } from "node:crypto";
import { URL } from "node:url";

export interface OAuthWrapperOptions {
  mcpTarget?: string;
  token?: string;
  port?: number;
  publicUrl?: string;
  /** Registered OAuth client id (confidential client). */
  clientId?: string;
  /** Registered OAuth client secret — required to exchange any grant. */
  clientSecret?: string;
}

interface IssuedCode {
  challenge: string | undefined;
  clientId: string;
  expiresAt: number;
}

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function startOAuthWrapper(
  options: OAuthWrapperOptions = {},
): http.Server {
  const mcpTarget =
    options.mcpTarget ?? process.env.MCP_TARGET ?? "http://127.0.0.1:8787";
  const token =
    options.token ??
    process.env.NEXQL_MCP_HTTP_TOKEN ??
    process.env.MCP_TOKEN ??
    "";
  // Confidential client credentials: required on /token for every grant.
  // Fallback keeps older deployments working when OAUTH_* env is not set.
  const clientId =
    options.clientId ?? process.env.OAUTH_CLIENT_ID ?? "mcp-client";
  const clientSecret =
    options.clientSecret ?? process.env.OAUTH_CLIENT_SECRET ?? token;
  const port = options.port ?? Number(process.env.OAUTH_PORT ?? 3000);
  const publicUrl = (
    options.publicUrl ??
    process.env.PUBLIC_URL ??
    "https://mcp-postgres.tailadac87.ts.net"
  ).replace(/\/$/, "");
  const redirectAllowlist = [
    /^https:\/\/claude\.ai\/api\/mcp\/auth_callback$/,
    /^https:\/\/chatgpt\.com\/connector\/oauth\/[^/]+$/,
    /^https:\/\/chat\.openai\.com\/.+auth_callback.*$/,
    /^https:\/\/chatgpt\.com\/.+auth_callback.*$/,
  ];

  function json(res: http.ServerResponse, obj: unknown, status = 200) {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
    });
    res.end(JSON.stringify(obj));
  }

  const codes = new Map<string, IssuedCode>();

  function handleWellKnownAuthServer(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
  ) {
    json(res, {
      issuer: publicUrl,
      authorization_endpoint: `${publicUrl}/authorize`,
      token_endpoint: `${publicUrl}/token`,
      scopes_supported: ["mcp.read", "mcp.write", "offline_access"],
      response_types_supported: ["code"],
      grant_types_supported: [
        "authorization_code",
        "client_credentials",
        "refresh_token",
      ],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
      ],
      code_challenge_methods_supported: ["S256"],
    });
  }

  function handleWellKnownProtectedResource(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
  ) {
    json(res, {
      resource: `${publicUrl}/mcp`,
      authorization_servers: [publicUrl],
      scopes_supported: ["mcp.read", "mcp.write"],
      bearer_methods_supported: ["header"],
    });
  }

  function handleRegister(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
  ) {
    // Dynamic Client Registration is disabled: clients must use the
    // pre-provisioned OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET pair.
    json(
      res,
      {
        error: "access_denied",
        error_description:
          "dynamic registration disabled — configure the connector with the provisioned OAuth Client ID and Client Secret",
      },
      403,
    );
  }

  /**
   * Extracts and validates client credentials from an HTTP Basic header or
   * urlencoded body parameters. Returns null when the pair does not match.
   */
  function validateClient(
    req: http.IncomingMessage,
    params: URLSearchParams,
  ): { id: string; ok: boolean } {
    const auth = req.headers.authorization ?? "";
    let basicId = "";
    let basicSecret = "";
    if (auth.startsWith("Basic ")) {
      try {
        const decoded = Buffer.from(auth.slice(6), "base64").toString();
        basicId = decoded.split(":")[0] ?? "";
        basicSecret = decoded.split(":").slice(1).join(":");
      } catch {
        // fall through to body params
      }
    }
    const id = params.get("client_id") || basicId || "";
    const secret = params.get("client_secret") || basicSecret || "";
    if (!id || !secret) return { id, ok: false };
    return { id, ok: id === clientId && secret === clientSecret };
  }

  function handleAuthorize(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ) {
    const url = new URL(req.url ?? "/", publicUrl);
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state");
    const codeChallenge = url.searchParams.get("code_challenge");
    const challengeMethod = url.searchParams.get("code_challenge_method");
    const clientIdParam = url.searchParams.get("client_id") || "claude-ai";

    if (clientIdParam !== clientId) {
      json(
        res,
        {
          error: "invalid_client",
          error_description:
            "unknown client_id — use the provisioned OAuth Client ID",
        },
        401,
      );
      return;
    }
    if (!redirectUri) {
      json(
        res,
        { error: "invalid_request", error_description: "missing redirect_uri" },
        400,
      );
      return;
    }
    if (!redirectAllowlist.some((re) => re.test(redirectUri))) {
      json(
        res,
        {
          error: "invalid_request",
          error_description: `redirect_uri not allowed for this connector: ${redirectUri}`,
        },
        400,
      );
      return;
    }
    if (!codeChallenge || challengeMethod !== "S256") {
      json(
        res,
        {
          error: "invalid_request",
          error_description: "PKCE S256 code_challenge is required",
        },
        400,
      );
      return;
    }
    const code =
      Math.random().toString(36).slice(2, 12) +
      Math.random().toString(36).slice(2, 12);
    codes.set(code, {
      challenge: codeChallenge,
      clientId: clientIdParam,
      expiresAt: Date.now() + 300000,
    });
    setTimeout(() => codes.delete(code), 300000);
    const redirect = new URL(redirectUri);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);
    res.writeHead(302, { Location: redirect.toString() });
    res.end();
  }

  function handleToken(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const grant = params.get("grant_type");

      // Every grant requires valid confidential client credentials.
      const client = validateClient(req, params);
      if (!client.ok) {
        json(
          res,
          {
            error: "invalid_client",
            error_description:
              "valid OAuth Client ID and Client Secret are required",
          },
          401,
        );
        return;
      }

      if (grant === "authorization_code") {
        const code = params.get("code");
        const verifier = params.get("code_verifier");
        const issued = code ? codes.get(code) : undefined;
        if (!issued) {
          json(res, { error: "invalid_grant" }, 400);
          return;
        }
        codes.delete(code!); // one-time use
        if (
          !verifier ||
          !issued.challenge ||
          s256(verifier) !== issued.challenge
        ) {
          json(
            res,
            {
              error: "invalid_grant",
              error_description: "PKCE verification failed",
            },
            400,
          );
          return;
        }
        json(res, {
          access_token: token,
          refresh_token:
            Math.random().toString(36).slice(2) +
            Math.random().toString(36).slice(2),
          token_type: "Bearer",
          expires_in: 3600,
          scope: "mcp.read mcp.write offline_access",
        });
        return;
      }

      if (grant === "client_credentials" || grant === "refresh_token") {
        json(res, {
          access_token: token,
          refresh_token:
            Math.random().toString(36).slice(2) +
            Math.random().toString(36).slice(2),
          token_type: "Bearer",
          expires_in: 3600,
          scope: "mcp.read mcp.write offline_access",
        });
        return;
      }

      json(res, { error: "unsupported_grant_type" }, 400);
    });
  }

  function proxyToMcp(req: http.IncomingMessage, res: http.ServerResponse) {
    const target = new URL(req.url ?? "/", mcpTarget);
    const opts: http.RequestOptions = {
      hostname: target.hostname,
      port: target.port,
      path: target.pathname + target.search,
      method: req.method,
      headers: { ...req.headers, host: target.host },
    };
    const proxyReq = http.request(opts, (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    });
    proxyReq.on("error", (e: Error) => {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "bad_gateway", message: e.message }));
    });
    req.pipe(proxyReq);
  }

  const server = http.createServer((req, res) => {
    console.log(
      `[oauth-wrapper] ${req.method} ${req.url} Host:${req.headers.host}`,
    );
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
      });
      res.end();
      return;
    }
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const path = url.pathname;
    if (
      path === "/.well-known/oauth-authorization-server" ||
      path === "/.well-known/oauth-authorization-server/"
    ) {
      handleWellKnownAuthServer(req, res);
      return;
    }
    if (
      path === "/.well-known/oauth-protected-resource" ||
      path === "/.well-known/oauth-protected-resource/"
    ) {
      handleWellKnownProtectedResource(req, res);
      return;
    }
    if (path === "/register") {
      handleRegister(req, res);
      return;
    }
    if (path === "/authorize" && req.method === "GET") {
      handleAuthorize(req, res);
      return;
    }
    if (path === "/token" && req.method === "POST") {
      handleToken(req, res);
      return;
    }
    proxyToMcp(req, res);
  });

  server.listen(port, "0.0.0.0", () => {
    console.log(
      `[oauth-wrapper] listening on 0.0.0.0:${port} → ${mcpTarget}, public ${publicUrl}, client ${clientId}`,
    );
  });
  return server;
}
