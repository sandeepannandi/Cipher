const fs = require('fs');
const path = require('path');
const os = require('os');

function findBinaryPath() {
  const binaryName = os.platform() === 'win32' ? 'cipher.exe' : 'cipher';

  // Priority 1: In the same directory as this npm package (local development)
  const pkgDir = path.join(__dirname, '..', '..');
  const localBin = path.join(pkgDir, '..', 'target', 'debug', binaryName);
  if (fs.existsSync(localBin)) {
    return path.resolve(localBin);
  }

  const releaseBin = path.join(pkgDir, '..', 'target', 'release', binaryName);
  if (fs.existsSync(releaseBin)) {
    return path.resolve(releaseBin);
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
