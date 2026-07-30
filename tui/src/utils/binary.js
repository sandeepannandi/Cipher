const fs = require('fs');
const path = require('path');
const os = require('os');

const isWin = os.platform() === 'win32';

/**
 * Convert a Windows path (C:\foo\bar) to a WSL Linux path (/mnt/c/foo/bar).
 * Non-Windows paths and paths without a drive letter are returned as-is.
 */
function toWslPath(winPath) {
  if (!isWin) return winPath;
  return winPath.replace(/^([A-Za-z]):\\/, (_, d) => `/mnt/${d.toLowerCase()}/`)
                .replace(/\\/g, '/');
}

/**
 * Find the cipher-ai binary, preferring the WSL-built Linux binary
 * so users don't need a working Windows native build.
 * Returns an object { path, useWSL } where useWSL indicates whether
 * the caller should prefix the command with 'wsl'.
 */
function findBinaryPath() {
  const binaryName = 'cipher-ai';       // WSL binary has no .exe
  const winBinaryName = 'cipher-ai.exe';

  // Priority 1: WSL-built Linux binary (compiled via cargo under WSL)
  // These are native Linux binaries that need 'wsl' prefix on Windows
  const wslPaths = [
    // From dist/ (bundled)
    path.resolve(__dirname, '..', '..', 'target', 'x86_64-unknown-linux-gnu', 'release', binaryName),
    // From src/utils/ (unbundled)
    path.resolve(__dirname, '..', '..', '..', 'target', 'x86_64-unknown-linux-gnu', 'release', binaryName),
  ];

  for (const p of wslPaths) {
    if (fs.existsSync(p)) {
      return { path: toWslPath(path.resolve(p)), useWSL: true };
    }
  }

  // Priority 2: Windows native binary (cipher-ai.exe)
  const winPaths = [
    // From dist/ (bundled)
    path.resolve(__dirname, '..', '..', 'target', 'release', winBinaryName),
    path.resolve(__dirname, '..', '..', 'target', 'debug', winBinaryName),
    path.resolve(__dirname, '..', '..', 'target', 'x86_64-pc-windows-gnullvm', 'release', winBinaryName),
    path.resolve(__dirname, '..', '..', 'target', 'x86_64-pc-windows-gnu', 'release', winBinaryName),
    // From src/utils/ (unbundled)
    path.resolve(__dirname, '..', '..', '..', 'target', 'release', winBinaryName),
    path.resolve(__dirname, '..', '..', '..', 'target', 'debug', winBinaryName),
    path.resolve(__dirname, '..', '..', '..', 'target', 'x86_64-pc-windows-gnullvm', 'release', winBinaryName),
    path.resolve(__dirname, '..', '..', '..', 'target', 'x86_64-pc-windows-gnu', 'release', winBinaryName),
  ];

  for (const p of winPaths) {
    if (fs.existsSync(p)) return { path: path.resolve(p), useWSL: false };
  }

  // Priority 3: Installed globally via npm (in ~/.cipher/bin/)
  const homeDir = os.homedir();
  const globalWsl = path.join(homeDir, '.cipher', 'bin', binaryName);
  if (fs.existsSync(globalWsl)) {
    return { path: toWslPath(path.resolve(globalWsl)), useWSL: isWin };
  }
  const globalWin = path.join(homeDir, '.cipher', 'bin', winBinaryName);
  if (fs.existsSync(globalWin)) {
    return { path: path.resolve(globalWin), useWSL: false };
  }

  // Priority 4: In PATH (system-wide installation)
  try {
    // First try the Windows binary
    const which = require('child_process').execFileSync(
      isWin ? 'where' : 'which',
      [winBinaryName],
      { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 }
    );
    const found = which.split('\n')[0].trim();
    if (found && fs.existsSync(found)) {
      return { path: path.resolve(found), useWSL: false };
    }
  } catch {
    // Try WSL binary name
    try {
      const which = require('child_process').execFileSync(
        isWin ? 'where' : 'which',
        [binaryName],
        { encoding: 'utf-8', stdio: 'pipe', timeout: 5000 }
      );
      const found = which.split('\n')[0].trim();
      if (found && fs.existsSync(found)) {
        return { path: toWslPath(path.resolve(found)), useWSL: isWin };
      }
    } catch {
      // Not in PATH
    }
  }

  return null;
}

module.exports.findBinaryPath = findBinaryPath;
