function findDelimiterEnd(
  text: string,
  openIndex: number,
  open: "{" | "[",
  close: "}" | "]",
): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let i = openIndex; i < text.length; i += 1) {
    const c = text[i];
    const next = text[i + 1];
    if (lineComment) {
      if (c === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (c === "*" && next === "/") {
        blockComment = false;
        i += 1;
      }
      continue;
    }
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c === "\\") {
        escaped = true;
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === "/" && next === "/") {
      lineComment = true;
      i += 1;
      continue;
    }
    if (c === "/" && next === "*") {
      blockComment = true;
      i += 1;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === open) depth += 1;
    else if (c === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Replaces comment characters with spaces, preserving newlines and therefore
 * every byte offset of the original text. Strings are left untouched. Used to
 * locate real code positions (object braces, section keys) in HuJSON without
 * matching braces or keys that only appear inside comments.
 */
export function stripHuJsonComments(raw: string): string {
  let cleaned = "";
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw[i]!;
    const next = raw[i + 1];
    if (lineComment) {
      if (c === "\n") {
        lineComment = false;
        cleaned += c;
      } else cleaned += " ";
      continue;
    }
    if (blockComment) {
      if (c === "*" && next === "/") {
        blockComment = false;
        cleaned += "  ";
        i += 1;
      } else cleaned += c === "\n" ? "\n" : " ";
      continue;
    }
    if (inString) {
      cleaned += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === "/" && next === "/") {
      lineComment = true;
      cleaned += "  ";
      i += 1;
    } else if (c === "/" && next === "*") {
      blockComment = true;
      cleaned += "  ";
      i += 1;
    } else {
      cleaned += c;
      if (c === '"') inString = true;
    }
  }
  return cleaned;
}

function indentOf(text: string, index: number): string {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  const match = /^[\t ]*/.exec(text.slice(lineStart, index));
  return match ? match[0] : "";
}

function withTrailingComma(body: string): string {
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  let lastCode = -1;
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i]!;
    const next = body[i + 1];
    if (lineComment) {
      if (c === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (c === "*" && next === "/") {
        blockComment = false;
        i += 1;
      }
      continue;
    }
    if (inString) {
      lastCode = i;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === "/" && next === "/") {
      lineComment = true;
      i += 1;
      continue;
    }
    if (c === "/" && next === "*") {
      blockComment = true;
      i += 1;
      continue;
    }
    if (c === '"') inString = true;
    if (!/\s/.test(c)) lastCode = i;
  }
  if (lastCode === -1 || body[lastCode] === ",") return body;
  return `${body.slice(0, lastCode + 1)},${body.slice(lastCode + 1)}`;
}

export type HuJsonSectionShape = "object" | "array";

export function parseHuJson<T = unknown>(raw: string): T {
  const cleaned = stripHuJsonComments(raw);

  let json = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < cleaned.length; i += 1) {
    const c = cleaned[i]!;
    if (inString) {
      json += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    if (c === ",") {
      let next = i + 1;
      while (next < cleaned.length && /\s/.test(cleaned[next]!)) next += 1;
      if (cleaned[next] === "}" || cleaned[next] === "]") continue;
    }
    json += c;
  }
  return JSON.parse(json) as T;
}

/**
 * Merge `items` into the `key` section (`{...}` object or `[...]` array) of a
 * HuJSON document while preserving existing comments, formatting and trailing
 * commas. Each item is a pre-rendered line, e.g. `"tag:ci": ["tag:admin"]` or
 * `{ "target": ["tag:ci"], "attr": ["funnel"] }`. Returns the original text
 * unchanged when the target cannot be located.
 */
export function ensureHuJsonSection(
  raw: string,
  key: string,
  items: string[],
  shape: HuJsonSectionShape = "object",
): string {
  const nonEmpty = items.map((item) => item.trim()).filter(Boolean);
  if (!nonEmpty.length) return raw;
  const openChar = shape === "array" ? "[" : "{";
  const closeChar = shape === "array" ? "]" : "}";
  const render = (indent: string): string =>
    nonEmpty.map((line) => `${indent}${line}`).join(",\n");

  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Locate real code positions only: a `"tagOwners": {` that appears inside a
  // comment must never be treated as the live section, otherwise the merge is
  // injected into the comment and the remote policy stays unchanged.
  const code = stripHuJsonComments(raw);
  const keyMatch = new RegExp(`"${escapedKey}"\\s*:[\\s]*([{[])`).exec(code);

  if (keyMatch) {
    const open = keyMatch.index + keyMatch[0].lastIndexOf(openChar);
    if (open === -1) return raw;
    const close = findDelimiterEnd(raw, open, openChar, closeChar);
    if (close === -1) return raw;
    const body = raw.slice(open + 1, close);
    const closingIndent = indentOf(raw, close);
    if (!body.trim()) {
      const innerIndent = `${closingIndent}  `;
      const replacement = `${openChar}\n${render(innerIndent)}\n${closingIndent}${closeChar}`;
      return `${raw.slice(0, open)}${replacement}${raw.slice(close + 1)}`;
    }
    const insert = nonEmpty
      .map((line) => `${closingIndent}${line},`)
      .join("\n");
    const separatedBody = withTrailingComma(body);
    return `${raw.slice(0, open + 1)}${separatedBody}${separatedBody.endsWith("\n") ? "" : "\n"}${insert}\n${raw.slice(close)}`;
  }

  const firstOpen = code.indexOf("{");
  if (firstOpen === -1) return raw;
  const outerIndent = indentOf(raw, firstOpen);
  const inner = `${outerIndent}  `;
  const deeper = `${inner}  `;
  const block = `${openChar}\n${render(deeper)}\n${inner}${closeChar}`;
  return `${raw.slice(0, firstOpen + 1)}\n${inner}"${key}": ${block},\n${raw.slice(firstOpen + 1)}`;
}

export function ensureHuJsonKey(
  raw: string,
  key: string,
  entries: Record<string, string[]>,
): string {
  return ensureHuJsonSection(
    raw,
    key,
    Object.entries(entries).map(
      // Escape both halves: tag names come from unvalidated TS_TAGS input and
      // a quote or backslash would otherwise produce broken HuJSON.
      ([name, value]) => `${JSON.stringify(name)}: ${JSON.stringify(value)}`,
    ),
    "object",
  );
}

export function ensureHuJsonArrayItem(
  raw: string,
  key: string,
  item: unknown,
): string {
  return ensureHuJsonSection(raw, key, [JSON.stringify(item)], "array");
}
