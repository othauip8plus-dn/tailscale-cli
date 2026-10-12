import { describe, expect, it } from "vitest";
import { renderPlist } from "../src/service/macos.js";
import type { ServiceConfig } from "../src/service/types.js";

const config: ServiceConfig = {
  name: "my-relay",
  user: "alice",
  workingDir: "/tmp",
  args: ["relay"],
  env: {},
  restart: { onFailure: true, delaySeconds: 5, maxRetries: 3 },
};

const opts = {
  nodePath: "/usr/bin/node",
  cliPath: "/opt/cli.js",
  outLog: "/tmp/out.log",
  errLog: "/tmp/err.log",
};

describe("macOS launchd restart policy", () => {
  it("restarts only on failure when onFailure is true", () => {
    const plist = renderPlist(config, opts);
    expect(plist).toContain("<key>KeepAlive</key>");
    expect(plist).toContain("<key>SuccessfulExit</key>");
    expect(plist).toContain("<false/>");
    expect(plist).not.toMatch(/<key>SuccessfulExit<\/key>\s*<true\/>/);
  });

  it("never restarts when onFailure is false", () => {
    const plist = renderPlist(
      {
        ...config,
        restart: { onFailure: false, delaySeconds: 5, maxRetries: 3 },
      },
      opts,
    );
    expect(plist).toContain("<key>KeepAlive</key>\n  <false/>");
    expect(plist).not.toContain("SuccessfulExit");
  });
});
