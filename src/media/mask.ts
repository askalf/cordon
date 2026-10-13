// Image masking for known-subject requests (policy subjectMedia: "mask").
//
// A screenshot, a letter or a photo of a document carries the same identifiers as text, and
// the text checks cannot read pixels. In mask mode each image is read here (OCR, on this
// server, no network: the engine and the English model load from node_modules), every word
// that is part of a subject's identifier or a catalog entity is painted over, and the masked
// image is read AGAIN. The image goes out only when that second reading finds nothing; one
// more round of masking is tried, then the request is refused. Media that cannot be read
// here (a PDF, audio, a file, an image by URL or file id) is refused in mask mode.
//
// The OCR and image libraries are optional dependencies, loaded on first use. Without them
// mask mode refuses every image rather than letting one through unread.

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { Detector, RedactSet, Span } from "../types";
import { egressViolations, withSubjects, type CompiledSubjects } from "../subject";
import { detector as catalog } from "../detect";

/** A media part the request carries that this module cannot read. */
export class MediaRefusal extends Error {}

/** Most images masked in one request, most pixels per image, and the time one read may take. */
const MAX_IMAGES = 10;
const MAX_PIXELS = 30_000_000;
const OCR_TIMEOUT_MS = 30_000;
/** OCR reads small text poorly: images narrower than this are scaled up before reading. */
const MIN_READ_WIDTH = 1400;
/** Catalog types whose presence in a masked image refuses it (subject types always do). */
const VERIFY_TYPES = new Set(["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IBAN", "US_ROUTING", "STREET_ADDRESS"]);
const PAD = 3;

type ImageRef = { mime: string; bytes: Buffer; replace(mime: string, bytes: Buffer): void };

interface Word { text: string; bbox: { x0: number; y0: number; x1: number; y1: number } }
interface Line { words: Word[] }

let libs: Promise<{ sharp: any; createWorker: any; langPath: string }> | undefined;
let worker: Promise<any> | undefined;

function loadLibs() {
  libs ??= (async () => {
    try {
      const sharp = (await import("sharp")).default;
      const { createWorker } = await import("tesseract.js");
      const require = createRequire(import.meta.url);
      // An explicit local path: without one, tesseract.js fetches the model from a CDN.
      const langPath = join(dirname(require.resolve("@tesseract.js-data/eng/package.json")), "4.0.0_best_int");
      return { sharp, createWorker, langPath };
    } catch {
      libs = undefined;
      throw new MediaRefusal("image masking is not installed (sharp, tesseract.js, @tesseract.js-data/eng)");
    }
  })();
  return libs;
}

async function ocrWorker() {
  const { createWorker, langPath } = await loadLibs();
  worker ??= createWorker("eng", 1, { langPath, gzip: true, cacheMethod: "none", logger: () => {}, errorHandler: () => {} }).catch((e: unknown) => {
    worker = undefined;
    throw e;
  });
  return worker;
}

/** Read an image's lines of words. A read that takes too long restarts the worker and refuses. */
async function read(png: Buffer): Promise<{ lines: Line[]; text: string }> {
  const w = await ocrWorker();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new MediaRefusal("an image took too long to read")), OCR_TIMEOUT_MS);
  });
  try {
    const { data } = await Promise.race([w.recognize(png, {}, { blocks: true, text: true }), timeout]);
    const lines: Line[] = [];
    for (const b of data.blocks ?? []) for (const p of b.paragraphs ?? []) for (const l of p.lines ?? []) lines.push({ words: l.words ?? [] });
    return { lines, text: String(data.text ?? "") };
  } catch (e) {
    if (e instanceof MediaRefusal) {
      const stale = worker;
      worker = undefined;
      stale?.then((x: any) => x.terminate()).catch(() => {});
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** The words of each line that fall inside a detected span (subjects first, then the catalog). */
function wordsToMask(lines: Line[], det: Detector, sets: RedactSet[]): { words: Word[]; counts: Record<string, number> } {
  const out: Word[] = [];
  const counts: Record<string, number> = {};
  for (const line of lines) {
    let text = "";
    const at: Array<{ w: Word; start: number; end: number }> = [];
    for (const w of line.words) {
      if (text) text += " ";
      at.push({ w, start: text.length, end: text.length + w.text.length });
      text += w.text;
    }
    const spans: Span[] = det.detect(text, sets);
    for (const s of spans) {
      counts[s.type] = (counts[s.type] ?? 0) + 1;
      for (const a of at) if (a.start < s.end && s.start < a.end && !out.includes(a.w)) out.push(a.w);
    }
  }
  return { words: out, counts };
}

/** What a masked image's reading still holds: subject kinds from the egress check, and catalog types. */
function leftovers(lines: Line[], text: string, subjects: CompiledSubjects, det: Detector, sets: RedactSet[]): string[] {
  const found = new Set(egressViolations({ text }, subjects));
  for (const t of Object.keys(wordsToMask(lines, det, sets).counts)) if (t.startsWith("SUBJECT") || VERIFY_TYPES.has(t)) found.add(t);
  return [...found];
}

async function maskOne(img: ImageRef, subjects: CompiledSubjects, sets: RedactSet[], counts: Record<string, number>): Promise<number> {
  const { sharp } = await loadLibs();
  const det = withSubjects(catalog, subjects);
  let meta: any;
  try {
    meta = await sharp(img.bytes, { limitInputPixels: MAX_PIXELS }).metadata();
  } catch {
    throw new MediaRefusal("an image could not be decoded");
  }
  if (!meta.width || !meta.height) throw new MediaRefusal("an image has no size");
  // Work on one upright, possibly enlarged PNG; the masked result is sent in that form.
  const scale = meta.width < MIN_READ_WIDTH ? MIN_READ_WIDTH / meta.width : 1;
  const width = Math.round(meta.width * scale);
  const height = Math.round(meta.height * scale);
  if (width * height > MAX_PIXELS) throw new MediaRefusal("an image is too large to read");
  let png: Buffer = await sharp(img.bytes, { limitInputPixels: MAX_PIXELS }).rotate().resize(width, height).flatten({ background: "#ffffff" }).png().toBuffer();

  let masked = 0;
  for (let round = 0; round < 2; round++) {
    const first = await read(png);
    const { words, counts: found } = wordsToMask(first.lines, det, sets);
    for (const [t, n] of Object.entries(found)) counts[`IMAGE_${t}`] = (counts[`IMAGE_${t}`] ?? 0) + n;
    if (words.length) {
      const rects = words
        .map((w) => `<rect x="${Math.max(0, w.bbox.x0 - PAD)}" y="${Math.max(0, w.bbox.y0 - PAD)}" width="${w.bbox.x1 - w.bbox.x0 + 2 * PAD}" height="${w.bbox.y1 - w.bbox.y0 + 2 * PAD}" fill="#000"/>`)
        .join("");
      const overlay = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}">${rects}</svg>`);
      png = await sharp(png).composite([{ input: overlay }]).png().toBuffer();
      masked += words.length;
    }
    const again = await read(png);
    const left = leftovers(again.lines, again.text, subjects, det, sets);
    if (!left.length) {
      img.replace("image/png", png);
      return masked;
    }
    if (round === 1) throw new MediaRefusal(`an image still shows ${left.join(", ")} after masking`);
  }
  throw new MediaRefusal("an image could not be masked");
}

// ---- finding the media parts in a body ----

const DATA_URL = /^data:([a-z]+\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)$/i;
const IMAGE_MIME = new Set(["image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"]);

function fromDataUrl(url: string, set: (v: string) => void): ImageRef | MediaRefusal {
  const m = DATA_URL.exec(url);
  if (!m) return new MediaRefusal("an image given by URL cannot be read here");
  const mime = m[1].toLowerCase();
  if (!IMAGE_MIME.has(mime)) return new MediaRefusal(`a ${mime} data part cannot be read here`);
  return { mime, bytes: Buffer.from(m[2], "base64"), replace: (t, b) => set(`data:${t};base64,${b.toString("base64")}`) };
}

/** Every media part in a body, as an image to mask or the reason it cannot be. */
export function mediaParts(node: any, out: Array<ImageRef | MediaRefusal> = [], depth = 0): Array<ImageRef | MediaRefusal> {
  if (!node || typeof node !== "object" || depth > 64) return out;
  if (Array.isArray(node)) {
    for (const v of node) mediaParts(v, out, depth + 1);
    return out;
  }
  const t = node.type;
  if (t === "image" && node.source) {
    const s = node.source;
    if (s.type === "base64" && typeof s.data === "string" && IMAGE_MIME.has(String(s.media_type).toLowerCase()))
      out.push({ mime: String(s.media_type).toLowerCase(), bytes: Buffer.from(s.data, "base64"), replace: (m, b) => { s.media_type = m; s.data = b.toString("base64"); } });
    else out.push(new MediaRefusal(`an image given as ${s.type} cannot be read here`));
    return out;
  }
  if (t === "image_url") {
    const holder = node.image_url;
    const url = typeof holder === "string" ? holder : holder?.url;
    if (typeof url !== "string") out.push(new MediaRefusal("an image part has no URL"));
    else out.push(fromDataUrl(url, (v) => { if (typeof holder === "string") node.image_url = v; else holder.url = v; }));
    return out;
  }
  if (t === "input_image") {
    if (typeof node.image_url === "string") out.push(fromDataUrl(node.image_url, (v) => { node.image_url = v; }));
    else out.push(new MediaRefusal("an image given by file id cannot be read here"));
    return out;
  }
  if (t === "document" && node.source && node.source.type !== "text" && node.source.type !== "content") {
    out.push(new MediaRefusal("a document given as a file cannot be read here"));
    return out;
  }
  if (t === "input_file" || t === "file" || t === "input_audio" || t === "audio" || t === "image_generation_call") {
    out.push(new MediaRefusal(`a ${t} part cannot be read here`));
    return out;
  }
  for (const v of Object.values(node)) mediaParts(v, out, depth + 1);
  return out;
}

/**
 * Mask every image in a de-identified body in place. Resolves to the number of words masked
 * (with per-type counts added to `counts` as IMAGE_<TYPE>); throws MediaRefusal when any media
 * part cannot be read, or an image still shows an identifier after two rounds.
 */
export async function maskMedia(body: any, subjects: CompiledSubjects, sets: RedactSet[], counts: Record<string, number>): Promise<number> {
  const parts = mediaParts(body);
  const refused = parts.find((p) => p instanceof MediaRefusal);
  if (refused) throw refused;
  if (parts.length > MAX_IMAGES) throw new MediaRefusal(`more than ${MAX_IMAGES} images in one request`);
  let masked = 0;
  for (const p of parts as ImageRef[]) masked += await maskOne(p, subjects, sets, counts);
  return masked;
}
