// Bundles the browser client into public/.
import * as esbuild from 'esbuild';
import fs from 'node:fs';

const watch = process.argv.includes('--watch');
fs.rmSync('public', { recursive: true, force: true });
fs.cpSync('client/static', 'public', { recursive: true });

const options = {
  entryPoints: ['client/dashboard.js', 'client/editor.js'],
  outdir: 'public',
  bundle: true,
  format: 'esm',
  target: 'es2022',
  minify: !watch,
  sourcemap: watch ? 'inline' : false,
  logLevel: 'info',
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
} else {
  await esbuild.build(options);
}
