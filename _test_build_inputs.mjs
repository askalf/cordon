// build.yml decides whether a PR owes the image build from the paths it changes. A path that
// slips past that decision skips the build while the required docker-build check still passes,
// so this runs the step's own script against scratch repositories and asserts the decision.
//
// The script is read out of the workflow rather than copied here, so the two cannot drift.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const workflow = readFileSync(path.join(root, '.github', 'workflows', 'build.yml'), 'utf8');

// The run: block of the step with id: diff, dedented.
function stepScript(y) {
  const lines = y.split('\n');
  const at = lines.findIndex((l) => /^\s+- id: diff$/.test(l));
  assert.ok(at >= 0, 'build.yml has no step with id: diff');
  const run = lines.findIndex((l, i) => i > at && /^\s+run: \|$/.test(l));
  assert.ok(run > at, 'the diff step has no run: | block');
  const indent = /^(\s*)/.exec(lines[run])[1].length;
  const body = [];
  for (const l of lines.slice(run + 1)) {
    if (l.trim() && /^(\s*)/.exec(l)[1].length <= indent) break;
    body.push(l);
  }
  const pad = Math.min(...body.filter((l) => l.trim()).map((l) => /^(\s*)/.exec(l)[1].length));
  return body.map((l) => l.slice(pad)).join('\n');
}

const script = stepScript(workflow);

const git = (cwd, ...args) => execFileSync('git', args, {
  cwd, encoding: 'utf8',
  env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' },
}).trim();

// A base commit, then a commit adding `files`; origin points at the repository itself so the
// script's fetch of the base sha resolves. Returns the script's changed= output.
function decide(files, event = 'pull_request') {
  const dir = mkdtempSync(path.join(tmpdir(), 'cordon-build-inputs-'));
  try {
    git(dir, 'init', '-q', '-b', 'main');
    git(dir, 'config', 'core.quotePath', 'true');
    writeFileSync(path.join(dir, 'README.md'), 'base\n');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'base');
    const base = git(dir, 'rev-parse', 'HEAD');
    for (const f of files) {
      mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      writeFileSync(path.join(dir, f), 'x\n');
    }
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'change');
    git(dir, 'remote', 'add', 'origin', pathToFileURL(dir).href);
    const out = path.join(dir, '.github-output');
    writeFileSync(out, '');
    const r = spawnSync('bash', ['-c', script], {
      cwd: dir, encoding: 'utf8',
      env: { ...process.env, EVENT: event, BASE_SHA: base, GITHUB_OUTPUT: out },
    });
    assert.equal(r.status, 0, `the step script failed:\n${r.stdout}${r.stderr}`);
    const m = /^changed=(.*)$/m.exec(readFileSync(out, 'utf8'));
    assert.ok(m, 'the step script wrote no changed= output');
    return m[1];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('an ordinary source change owes the image build', () => {
  assert.equal(decide(['src/a.ts']), 'true');
});

test('a source file with a non-ASCII name owes the image build', () => {
  assert.equal(decide(['src/café.ts']), 'true');
});

test('a source file whose name holds a tab or a newline owes the image build', { skip: process.platform === 'win32' }, () => {
  assert.equal(decide(['src/a\tb.ts']), 'true');
  assert.equal(decide(['src/a\nb.ts']), 'true');
});

test('each image input owes the build', () => {
  for (const f of ['Dockerfile', '.dockerignore', 'package.json', 'package-lock.json', 'tsconfig.json', '.github/workflows/build.yml'])
    assert.equal(decide([f]), 'true', f);
});

test('a docs-only change owes nothing, non-ASCII name or not', () => {
  assert.equal(decide(['docs/guide.md', 'README.md']), 'false');
  assert.equal(decide(['docs/café.md']), 'false');
});

test('a path that only contains an input name is not one', () => {
  assert.equal(decide(['docs/src/a.ts', 'examples/Dockerfile']), 'false');
});

test('a push always owes the image build', () => {
  assert.equal(decide(['docs/guide.md'], 'push'), 'true');
});
