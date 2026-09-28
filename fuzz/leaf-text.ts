import type { Dialect } from '../src/types';

/** Count in the same decoded domain as detection, but only at argument slots.
 * JSON-looking message text and strings inside decoded arguments stay literal.
 */
export function allLeafText(body: any, dialect: Dialect): string[] {
  const out: string[] = [];
  function walk(node: any, path: string[], decoded = false, depth = 0): void {
    if (depth > 20 || node == null) return;
    if (typeof node === 'string') {
      const argumentsSlot = !decoded && (
        (dialect === 'responses' && path.at(-1) === 'arguments' &&
          (path[0] === 'input' || (path[0] === 'prompt' && path[1] === 'variables'))) ||
        (dialect === 'chat' && path.length === 6 && path[0] === 'messages' &&
          path[2] === 'tool_calls' && path[4] === 'function' && path[5] === 'arguments')
      );
      if (argumentsSlot) {
        let parsed: unknown;
        try { parsed = JSON.parse(node); } catch { /* malformed arguments are plain text */ }
        // Production decodes objects/arrays only; JSON primitives use text fallback.
        if (parsed && typeof parsed === 'object') {
          walk(parsed, [], true, depth + 1);
          return;
        }
      }
      out.push(node);
    } else if (typeof node === 'number' || typeof node === 'bigint') out.push(String(node));
    else if (typeof node === 'object')
      for (const k of Object.keys(node)) walk(node[k], [...path, k], decoded, depth + 1);
  }
  walk(body, []);
  return out;
}
