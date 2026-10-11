import { config } from "../config";

/**
 * Which tool arguments reversible mode may put real values back into.
 *
 * cordon restores a value wherever the model put its placeholder, so a value can come
 * back inside an argument the caller did not expect it in (an email routed into a "to"
 * field). Deciding which destinations a tool may reach stays the runner's job; this is
 * the narrower lever cordon can offer: CORDON_RESTORE_TOOLS lists the tools, or
 * tool.field pairs (a top-level argument key), whose arguments are restored. Unset, empty
 * or "*" restores every tool's arguments. A value the policy withholds stays a
 * placeholder, which the tool receives as such.
 *
 * Tool names (OpenAI and Anthropic both allow [A-Za-z0-9_-]) carry no dot, so the first
 * dot separates the tool from the field.
 */
export interface RestorePolicy {
  /** True when every tool's arguments are restored (the default). */
  readonly all: boolean;
  /** For one tool (undefined: a call whose name the stream has not shown), whether a
   *  value at a top-level argument key may be restored. `key` is undefined for a
   *  position outside any top-level key (a plain-text input, a document that is not an
   *  object). */
  forTool(name: string | undefined): (key: string | undefined) => boolean;
}

const EVERYTHING: RestorePolicy = { all: true, forTool: () => () => true };

export function parseRestoreTools(raw: string | undefined): RestorePolicy {
  const s = (raw ?? "").trim();
  if (!s || s === "*") return EVERYTHING;
  // tool -> true (every field) or the set of fields
  const tools = new Map<string, true | Set<string>>();
  for (const entry of s.split(",").map((e) => e.trim()).filter(Boolean)) {
    const dot = entry.indexOf(".");
    if (dot === -1) {
      tools.set(entry, true);
      continue;
    }
    const tool = entry.slice(0, dot);
    const field = entry.slice(dot + 1);
    if (!tool || !field) continue;
    const cur = tools.get(tool);
    if (cur === true) continue;
    if (cur) cur.add(field);
    else tools.set(tool, new Set([field]));
  }
  return {
    all: false,
    forTool(name) {
      const rule = name === undefined ? undefined : tools.get(name);
      if (rule === undefined) return () => false;
      if (rule === true) return () => true;
      return (key) => key !== undefined && rule.has(key);
    },
  };
}

/** The policy from CORDON_RESTORE_TOOLS, read once at startup. */
export const restorePolicy: RestorePolicy = parseRestoreTools(config.restoreTools);
