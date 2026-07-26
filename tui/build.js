const esbuild = require('esbuild');
const path = require('path');

esbuild.build({
  entryPoints: [
    path.join(__dirname, 'src', 'index.jsx'),
  ],
  bundle: true,
  platform: 'node',
  target: 'node18',
  outdir: path.join(__dirname, 'dist'),
  external: ['ink', 'react'],
  format: 'cjs',
  loader: {
    '.jsx': 'jsx',
  },
}).catch(() => process.exit(1));
