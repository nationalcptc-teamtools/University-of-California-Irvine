// Builds the native incremental compile engine (engine/) into bin/typst-engine.
// Uses the project-local Rust toolchain in .rust/ if present, else the system one.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const local = path.join(root, '.rust');
const env = { ...process.env };
let cargo = 'cargo';
if (fs.existsSync(path.join(local, 'cargo', 'bin', 'cargo'))) {
  env.RUSTUP_HOME = path.join(local, 'rustup');
  env.CARGO_HOME = path.join(local, 'cargo');
  cargo = path.join(local, 'cargo', 'bin', 'cargo');
}
execFileSync(cargo, ['build', '--release'], { cwd: path.join(root, 'engine'), env, stdio: 'inherit' });
fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
// Write a new file and rename it into place: overwriting a binary in place
// makes macOS kill it on launch (its cached code signature no longer matches).
const target = path.join(root, 'bin', 'typst-engine');
const tmp = target + '.new';
fs.copyFileSync(path.join(root, 'engine', 'target', 'release', 'typst-engine'), tmp);
fs.chmodSync(tmp, 0o755);
fs.renameSync(tmp, target);
console.log('Built bin/typst-engine');
