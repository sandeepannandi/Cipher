const fs = require('fs');
const path = require('path');
const os = require('os');

function findBinaryPath() {
  const binaryName = os.platform() === 'win32' ? 'cipher-ai.exe' : 'cipher-ai';

  const searchPaths = [
    // From dist/ (bundled): ../../target/release/
    path.resolve(__dirname, '..', '..', 'target', 'release', binaryName),
    // From dist/ (bundled): ../../target/debug/
    path.resolve(__dirname, '..', '..', 'target', 'debug', binaryName),
    // From dist/ (bundled): ../../target/x86_64-pc-windows-gnullvm/release/
    path.resolve(__dirname, '..', '..', 'target', 'x86_64-pc-windows-gnullvm', 'release', binaryName),
    // From src/utils/ (unbundled): ../../../target/release/
    path.resolve(__dirname, '..', '..', '..', 'target', 'release', binaryName),
    // From src/utils/ (unbundled): ../../../target/debug/
    path.resolve(__dirname, '..', '..', '..', 'target', 'debug', binaryName),
    // From src/utils/ (unbundled): ../../../target/x86_64-pc-windows-gnullvm/release/
    path.resolve(__dirname, '..', '..', '..', 'target', 'x86_64-pc-windows-gnullvm', 'release', binaryName),
  ];

  for (const p of searchPaths) {
    if (fs.existsSync(p)) return path.resolve(p);
  }

  // Priority 2: Installed globally via npm (in ~/.cipher/bin/)
  const homeDir = os.homedir();
  const globalBin = path.join(homeDir, '.cipher', 'bin', binaryName);
  if (fs.existsSync(globalBin)) {
    return path.resolve(globalBin);
  }

  // Priority 3: In PATH (system-wide installation)
  try {
    const which = require('child_process').execFileSync(
      os.platform() === 'win32' ? 'where' : 'which',
      [binaryName],
      { encoding: 'utf-8', stdio: 'pipe' }
    );
    const found = which.split('\n')[0].trim();
    if (found && fs.existsSync(found)) {
      return found;
    }
  } catch {
    // Not in PATH
  }

  return null;
}

module.exports.findBinaryPath = findBinaryPath;
