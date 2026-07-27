#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

/**
 * Find the cipher-ai Rust binary.
 * Checks: local dev build → npm global install → system PATH
 */
function findBinaryPath() {
  const binaryName = os.platform() === 'win32' ? 'cipher-ai.exe' : 'cipher-ai';

  // Priority 1: Local dev build (target/debug/ or target/release/)
  const pkgDir = path.resolve(__dirname, '..');
  const searchPaths = [
    path.join(pkgDir, '..', 'target', 'release', binaryName),
    path.join(pkgDir, '..', 'target', 'debug', binaryName),
  ];
  for (const p of searchPaths) {
    if (fs.existsSync(p)) return path.resolve(p);
  }

  // Priority 2: npm global install (~/.cipher-ai/bin/)
  const homeDir = os.homedir();
  const globalBin = path.join(homeDir, '.cipher-ai', 'bin', binaryName);
  if (fs.existsSync(globalBin)) return path.resolve(globalBin);

  // Priority 3: System PATH
  try {
    const which = execFileSync(
      os.platform() === 'win32' ? 'where' : 'which',
      [binaryName],
      { encoding: 'utf-8', stdio: 'pipe' }
    );
    const found = which.split('\n')[0].trim();
    if (found && fs.existsSync(found)) return found;
  } catch {
    // Not in PATH
  }

  return null;
}

// If CLI arguments are given, run the Rust binary directly
const args = process.argv.slice(2);
if (args.length > 0) {
  const binaryPath = findBinaryPath();
  if (!binaryPath) {
    console.error(
      'CipherAI Rust binary not found.\n' +
      'Build it: cargo build --release\n' +
      'Or download from: https://github.com/sandeepannandi/Cipher/releases'
    );
    process.exit(1);
  }
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

// No arguments → launch the TUI (CJS bundle — just require it)
const distIndex = path.join(__dirname, '..', 'dist', 'index.js');
if (fs.existsSync(distIndex)) {
  require(distIndex);
} else {
  console.error(
    'CipherAI TUI not built yet. Run:\n' +
    '  cd tui && npm install\n' +
    '  npm run build\n' +
    'Then: node bin/cipher-ai.js'
  );
  process.exit(1);
}
