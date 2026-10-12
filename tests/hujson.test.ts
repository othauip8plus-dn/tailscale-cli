import { describe, expect, it } from "vitest";
import {
  ensureHuJsonArrayItem,
  ensureHuJsonKey,
  ensureHuJsonSection,
  parseHuJson as parseHuJsonDocument,
} from "../src/hujson.js";

function parseHuJson(text: string): unknown {
  const stripped = text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "")
    .replace(/,\s*([}\]])/g, "$1");
  return JSON.parse(stripped);
}

describe("ensureHuJsonKey", () => {
  it("parses comments and trailing commas without changing string contents", () => {
    expect(
      parseHuJsonDocument(`{/* note */ "value": ",}", "items": ["*",],}`),
    ).toEqual({
      value: ",}",
      items: ["*"],
    });
  });
  it("preserves comments when adding to an existing tagOwners block", () => {
    const raw = `{
  // comment at root
  "tagOwners": {
    "tag:ci": ["tag:admin"], // fires on CI
  },
  "autoApprovers": { "route": ["tag:ci"] },
}`;
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:build": ["tag:admin"],
    });
    expect(merged).toContain("// comment at root");
    expect(merged).toContain("// fires on CI");
    expect(merged).toContain('"tag:build": ["tag:admin"]');
    expect(parseHuJson(merged)).toEqual({
      tagOwners: { "tag:ci": ["tag:admin"], "tag:build": ["tag:admin"] },
      autoApprovers: { route: ["tag:ci"] },
    });
  });

  it("adds a separator when the existing object has no trailing comma", () => {
    const raw = `{
  "tagOwners": {
    "tag:ci": ["tag:admin"] // existing owner
  }
}`;
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:build": ["tag:admin"],
    });
    expect(parseHuJson(merged)).toEqual({
      tagOwners: {
        "tag:ci": ["tag:admin"],
        "tag:build": ["tag:admin"],
      },
    });
  });

  it("inserts a missing tagOwners block after the opening brace", () => {
    const raw = `// header only\n{\n  "ssh": [{ "action": "accept" }]\n}`;
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:ci": ["autogroup:admin"],
    });
    expect(merged).toContain("// header only");
    const parsed = parseHuJson(merged) as {
      tagOwners: Record<string, string[]>;
    };
    expect(parsed.tagOwners["tag:ci"]).toEqual(["autogroup:admin"]);
  });

  it("replaces an empty tagOwners object", () => {
    const raw = '{\n  "tagOwners": {},\n  "ssh": []\n}';
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:a": ["tag:admin"],
      "tag:b": ["autogroup:admin"],
    });
    expect(parseHuJson(merged)).toEqual({
      tagOwners: { "tag:a": ["tag:admin"], "tag:b": ["autogroup:admin"] },
      ssh: [],
    });
  });

  it("returns the raw text unchanged when the merge target cannot be located", () => {
    const raw = "// header comment only, no ACL object yet\n";
    expect(ensureHuJsonKey(raw, "tagOwners", { "tag:a": ["tag:admin"] })).toBe(
      raw,
    );
  });

  it("ignores braces inside comments when locating the section end", () => {
    const raw = `{
  // the closing brace below is only a comment: }
  "tagOwners": {
    "tag:ci": ["tag:admin"], // stays }
  },
  "autoApprovers": { "route": ["tag:ci"] },
}`;
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:build": ["tag:admin"],
    });
    expect(merged).toContain("// the closing brace below is only a comment: }");
    expect(merged).toContain("// stays }");
    expect(parseHuJson(merged)).toEqual({
      tagOwners: { "tag:ci": ["tag:admin"], "tag:build": ["tag:admin"] },
      autoApprovers: { route: ["tag:ci"] },
    });
  });

  it("does not match a key that only appears inside a comment", () => {
    const raw = `{
  // "tagOwners": {}
  "autoApprovers": {}
}`;
    const merged = ensureHuJsonKey(raw, "tagOwners", {
      "tag:a": ["tag:admin"],
    });
    const parsed = parseHuJson(merged) as {
      tagOwners: Record<string, string[]>;
    };
    expect(parsed.tagOwners).toEqual({ "tag:a": ["tag:admin"] });
  });
});

describe("ensureHuJsonArrayItem", () => {
  it("appends a nodeAttrs entry into an existing array while keeping comments", () => {
    const raw = `{
  // tailnet access control
  "nodeAttrs": [
    { "target": ["tag:ci"], "attr": ["funnel"] }, // usual CI node
  ],
  "tagOwners": {}
}`;
    const merged = ensureHuJsonArrayItem(raw, "nodeAttrs", {
      target: ["tag:build"],
      attr: ["funnel"],
    });
    expect(merged).toContain("// tailnet access control");
    expect(merged).toContain("// usual CI node");
    const parsed = parseHuJson(merged) as {
      nodeAttrs: { target: string[]; attr: string[] }[];
    };
    expect(parsed.nodeAttrs.map((e) => e.target[0])).toEqual([
      "tag:ci",
      "tag:build",
    ]);
  });

  it("adds a separator when the existing array has no trailing comma", () => {
    const raw = `{
  "nodeAttrs": [
    { "target": ["tag:ci"], "attr": ["funnel"] } /* existing */
  ]
}`;
    const merged = ensureHuJsonArrayItem(raw, "nodeAttrs", {
      target: ["tag:build"],
      attr: ["funnel"],
    });
    const parsed = parseHuJson(merged) as {
      nodeAttrs: { target: string[] }[];
    };
    expect(parsed.nodeAttrs.map((entry) => entry.target[0])).toEqual([
      "tag:ci",
      "tag:build",
    ]);
  });

  it("creates the nodeAttrs array when missing", () => {
    const raw = '{ "autoApprovers": {} }';
    const merged = ensureHuJsonArrayItem(raw, "nodeAttrs", {
      target: ["tag:ci"],
      attr: ["funnel"],
    });
    const parsed = parseHuJson(merged) as {
      nodeAttrs: { target: string[] }[];
      autoApprovers: Record<string, unknown>;
    };
    expect(parsed.nodeAttrs[0]!.target).toEqual(["tag:ci"]);
    expect(parsed.autoApprovers).toEqual({});
  });
});

describe("ensureHuJsonSection", () => {
  it("ignores empty item lists", () => {
    const raw = '{ "tagOwners": {} }';
    expect(ensureHuJsonSection(raw, "tagOwners", [])).toBe(raw);
    expect(ensureHuJsonSection(raw, "tagOwners", ["   "])).toBe(raw);
  });
});
