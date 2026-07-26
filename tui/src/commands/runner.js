const { execFile } = require('child_process');
const { findBinaryPath } = require('../utils/binary');

const BINARY_TIMEOUT_MS = 300_000; // 5 minutes

/**
 * Run a command against the Rust cipher binary.
 * @param {string[]} args - Command-line arguments
 * @param {{ silent?: boolean }} options - Options
 * @returns {Promise<{ ok: boolean, stdout: string, stderr: string, json?: any, error?: string }>}
 */
function runCommand(args, options = {}) {
  return new Promise((resolve) => {
    const binaryPath = findBinaryPath();
    if (!binaryPath) {
      resolve({
        ok: false,
        stdout: '',
        stderr: '',
        error: 'Cipher binary not found. Install it first.',
      });
      return;
    }

    // Ensure --json flag for machine-readable output unless it's an interactive command
    const cmdArgs = [...args];
    if (!cmdArgs.includes('--json') && !cmdArgs.includes('--format')) {
      cmdArgs.push('--json');
    }

    const child = execFile(
      binaryPath,
      cmdArgs,
      {
        cwd: process.cwd(),
        maxBuffer: 50 * 1024 * 1024, // 50MB
        timeout: BINARY_TIMEOUT_MS,
        encoding: 'utf-8',
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (error) {
          // Timeout
          if (error.killed) {
            resolve({
              ok: false,
              stdout: stdout || '',
              stderr: stderr || '',
              error: 'Command timed out after ' + (BINARY_TIMEOUT_MS / 1000) + 's',
            });
            return;
          }
          // Non-zero exit
          resolve({
            ok: false,
            stdout: stdout || '',
            stderr: stderr || error.message,
            error: error.message,
          });
          return;
        }

        const result = {
          ok: true,
          stdout: stdout || '',
          stderr: stderr || '',
        };

        // Try to parse JSON from stdout
        try {
          const parsed = JSON.parse(stdout);
          result.json = parsed;
        } catch {
          // Not JSON — that's fine, leave as plain text
        }

        resolve(result);
      }
    );

    // Kill child process if parent is interrupted
    process.on('SIGINT', () => {
      child.kill();
    });
  });
}

module.exports.runCommand = runCommand;
