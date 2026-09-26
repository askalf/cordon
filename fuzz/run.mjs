// `node fuzz/run.mjs` runs every Jazzer.js target in ./fuzz. This is the fuzzer CI runs
// (.github/workflows/fuzz.yml) and the local repro loop. Environment:
//   FUZZ_SECONDS       per-target budget in seconds (default 30)
//   FUZZ_CORPUS_DIR    root of per-target corpus dirs, created on demand; libFuzzer reads its
//                      seeds from <dir>/<target> and saves every interesting input there, so a
//                      corpus that persists between runs keeps getting deeper. Unset: defaults to
//                      fuzz/corpus/<target> (gitignored), so a local run never writes into the
//                      committed seed corpus.
//   FUZZ_ARTIFACT_DIR  where a crashing input is written, created on demand. Unset: the cwd.
//
// The targets are TypeScript (fuzz/*.fuzz.ts): each is bundled with esbuild to fuzz/build/<target>.fuzz.js
// first, exactly as .clusterfuzzlite/build.sh does, then Jazzer runs the bundle. A target's seed
// inputs in fuzz/seeds/<target> are passed as a second corpus directory: libFuzzer reads them and
// writes new inputs to the first (persisted) directory only.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const dir = path.dirname(fileURLToPath(import.meta.url));
const targets = readdirSync(dir).filter((f) => f.endsWith('.fuzz.ts')).map((f) => f.replace(/\.fuzz\.ts$/, '')).sort();
const secs = process.env.FUZZ_SECONDS || '30';
const corpusRoot = process.env.FUZZ_CORPUS_DIR || path.join(dir, 'corpus');
const artifactDir = process.env.FUZZ_ARTIFACT_DIR || '';
// Run Jazzer's JS CLI directly under `node`: no .cmd wrapper, no shell. esbuild is called through
// its JS API (its bin/ entry is the native binary once installed, not a script).
const jazzerCli = createRequire(import.meta.url).resolve('@jazzer.js/core/dist/cli.js');
mkdirSync(path.join(dir, 'build'), { recursive: true });
if (artifactDir) mkdirSync(artifactDir, { recursive: true });

for (const name of targets) {
  const bundle = `fuzz/build/${name}.fuzz.js`;
  try {
    await build({ entryPoints: [`fuzz/${name}.fuzz.ts`], bundle: true, format: 'esm', platform: 'node', target: 'node20', outfile: bundle, logLevel: 'warning' });
  } catch (err) {
    console.error(`\n${name}: esbuild failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  // The targets are synchronous (they never return a promise), so Jazzer runs in --sync mode.
  const args = [jazzerCli, `fuzz/build/${name}.fuzz`, '--sync'];
  const corpus = path.join(corpusRoot, name);
  mkdirSync(corpus, { recursive: true });
  args.push(corpus);
  const seeds = path.join(dir, 'seeds', name);
  if (existsSync(seeds)) args.push(seeds);
  args.push('--', `-max_total_time=${secs}`, '-print_final_stats=1');
  if (artifactDir) args.push(`-artifact_prefix=${artifactDir}${path.sep}`);
  console.log(`\n=== fuzzing ${name} (${secs}s) ===`);
  const r = spawnSync(process.execPath, args, { stdio: 'inherit' });
  if (r.status !== 0) {
    console.error(`\n${name}: jazzer exited with ${r.status ?? r.signal}; a reproducing input is in ${artifactDir || 'the working directory'}`);
    process.exit(r.status || 1);
  }
}
