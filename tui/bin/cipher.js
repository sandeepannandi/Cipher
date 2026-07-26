#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

// Find the cipher binary with fallback for dev mode
function findBinary() {
  // Try built dist first, then fallback to source (dev mode)
  let binaryModule;
  const distPath = path.join(__dirname, '..', 'dist', 'utils', 'binary.js');
  const srcPath = path.join(__dirname, '..', 'src', 'utils', 'binary.js');

  if (fs.existsSync(distPath)) {
    binaryModule = require(distPath);
  } else if (fs.existsSync(srcPath)) {
    binaryModule = require(srcPath);
  } else {
    console.error(
      'Cipher TUI not built yet. Run:\n' +
      '  cd tui && npm install && npm run build'
    );
    process.exit(1);
  }

  const bin = binaryModule.findBinaryPath();
  if (bin) return bin;

  console.error(
    'Cipher Rust binary not found.\n' +
    'Build it: cargo build --release\n' +
    'Or download from: https://github.com/sandeepannandi/Cipher/releases'
  );
  process.exit(1);
}

// If CLI arguments are given, run the Rust binary directly
const args = process.argv.slice(2);
if (args.length > 0) {
  const binaryPath = findBinary();
  try {
    execFileSync(binaryPath, args, {
      encoding: 'utf-8',
      stdio: 'inherit',
      cwd: process.cwd(),
    });
    process.exit(0);
  } catch (err) {
    process.exit(err.status || 1);
  }
}

// No arguments → launch the TUI
try {
  require('../dist/index');
} catch {
  // Dev mode: run from source (requires npm link)
  try {
    require('../src/index.dev');
  } catch {
    console.error(
      'Cipher TUI not built yet. Run:\n' +
      '  cd tui && npm install && npm run build\n' +
      'Or use CLI mode: cipher --help'
    );
    process.exit(1);
  }
}
