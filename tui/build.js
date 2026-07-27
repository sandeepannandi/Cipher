const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');

async function build() {
  // Clean old dist files first
  const distDir = path.join(__dirname, 'dist');
  if (fs.existsSync(distDir)) {
    for (const file of fs.readdirSync(distDir)) {
      const filePath = path.join(distDir, file);
      if (fs.statSync(filePath).isFile()) {
        fs.unlinkSync(filePath);
      }
    }
  }

  // Bundle the TUI app → dist/index.js (CJS)
  // Ink 3 is CJS-based, React 17 is CJS — no ESM issues
  await esbuild.build({
    entryPoints: [
      path.join(__dirname, 'src', 'index.jsx'),
    ],
    bundle: true,
    platform: 'node',
    target: 'node18',
    outdir: path.join(__dirname, 'dist'),
    format: 'cjs',
    external: ['ink', 'react'],
    loader: {
      '.jsx': 'jsx',
    },
  });

  console.log('✓ Built dist/index.js');
}

build().catch(() => process.exit(1));
