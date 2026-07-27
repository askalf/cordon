#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
#
# The targets cover cordon's trust boundary — the pipeline that parses UNTRUSTED
# prompt text — and their invariants are its fail-closed contracts:
#   detect_spans      the detector never throws on hostile bytes, and every span
#                     it returns is well-formed, in-range, sorted, non-overlapping
#                     and from an ACTIVE set (replaceSpans corrupts the body
#                     otherwise);
#   redact_leak       no value the detector claimed survives into the body that
#                     is forwarded upstream — the product guarantee — plus no
#                     prototype pollution from a hostile leaf key;
#   reidentify_stream restoring a stream through arbitrary chunk splits equals
#                     restoring it whole (the split-placeholder bug class).
cd "$SRC/cordon"

# cordon ships a committed package-lock.json, so the build is lockfile-exact:
# `npm ci` (never `npm install`) so a lockfile drift fails the fuzz build instead
# of silently resolving fresh versions. @jazzer.js/core and esbuild are pinned
# devDependencies in that lockfile.
npm ci --no-audit --no-fund

# cordon is TypeScript, and `compile_javascript_fuzzer` wraps a target for plain
# node — which cannot resolve either the .ts extension or the extensionless
# imports the source uses (tsconfig moduleResolution: Bundler). tsc alone would
# not help: it preserves those specifiers verbatim in its output. So bundle each
# target into a self-contained ESM .js first. Bundling also pulls src/ in, so the
# fuzzer runs the real modules, not stubs.
mkdir -p fuzz/build
for target in detect_spans redact_leak reidentify_stream; do
  ./node_modules/.bin/esbuild "fuzz/${target}.fuzz.ts" \
    --bundle \
    --format=esm \
    --platform=node \
    --target=node20 \
    --outfile="fuzz/build/${target}.fuzz.js"
done

# --sync: every target's fuzz() is synchronous (detection, redaction and stream
# re-identification are all sync). An async target would omit this flag.
for target in detect_spans redact_leak reidentify_stream; do
  compile_javascript_fuzzer cordon "fuzz/build/${target}.fuzz.js" --sync
  # Seed corpus: random bytes essentially never synthesise a Luhn-valid card or a
  # well-formed email, so without seeds the entity-bearing paths would almost
  # never be reached and the leak/round-trip invariants would idle.
  if [ -d "fuzz/seeds/${target}" ]; then
    zip -j "$OUT/${target}.fuzz_seed_corpus.zip" "fuzz/seeds/${target}"/* >/dev/null
  fi
done
