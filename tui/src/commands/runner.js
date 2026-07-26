const { execFile } = require('child_process');
const { findBinaryPath } = require('../utils/binary');

const BINARY_TIMEOUT_MS = 300_000; // 5 minutes

/**
 * Run a command against the Rust cipher binary.
 * Passes arguments through exactly as provided — no flags added.
 * @param {string[]} args - Command-line arguments (passed as-is to the binary)
 * @returns {Promise<{ ok: boolean, stdout: string, stderr: string, error?: string }>}
 */
function runCommand(args) {
  return new Promise((resolve) => {
    const binaryPath = findBinaryPath();
    if (!binaryPath) {
      resolve({
        ok: false,
        stdout: '',
        stderr: '',
        error: 'Cipher Rust binary not found. Build it: cargo build --release',
      });
      return;
    }

    const child = execFile(
      binaryPath,
      args,
      {
        cwd: process.cwd(),
        maxBuffer: 50 * 1024 * 1024,
        timeout: BINARY_TIMEOUT_MS,
        encoding: 'utf-8',
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (error) {
          if (error.killed) {
            resolve({
              ok: false,
              stdout: stdout || '',
              stderr: stderr || '',
              error: 'Command timed out after ' + (BINARY_TIMEOUT_MS / 1000) + 's',
            });
            return;
          }
          resolve({
            ok: false,
            stdout: stdout || '',
            stderr: stderr || error.message,
            error: error.message,
          });
          return;
        }

        resolve({
          ok: true,
          stdout: stdout || '',
          stderr: stderr || '',
        });
      }
    );

    // Kill child process if parent is interrupted
    process.on('SIGINT', () => {
      child.kill();
    });
  });
}

module.exports.runCommand = runCommand;
