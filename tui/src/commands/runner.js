const { spawn } = require('child_process');
const { findBinaryPath } = require('../utils/binary');

const BINARY_TIMEOUT_MS = 120_000; // 2 minutes (reduced from 5)
const MAX_STDOUT_BYTES = 10 * 1024 * 1024; // 10MB max buffered output
const MAX_STDERR_BYTES = 5 * 1024 * 1024;  // 5MB max buffered stderr

/**
 * Run a command against the Rust cipher binary.
 * Uses spawn for streaming — won't hang the event loop.
 * Supports AbortSignal for cancellation.
 *
 * @param {string[]} args - Command-line arguments
 * @param {AbortSignal} [signal] - Optional AbortSignal to cancel the command
 * @returns {Promise<{ ok: boolean, stdout: string, stderr: string, error?: string }>}
 */
function runCommand(args, signal) {
  return new Promise((resolve) => {
    const result = findBinaryPath();
    if (!result) {
      resolve({
        ok: false,
        stdout: '',
        stderr: '',
        error: 'CipherAI Rust binary not found. Build it: cargo build --release',
      });
      return;
    }

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let killed = false;
    const timers = [];

    // If useWSL is true, prefix the command with 'wsl'
    const command = result.useWSL ? 'wsl' : result.path;
    const cmdArgs = result.useWSL ? [result.path, ...args] : args;

    const child = spawn(command, cmdArgs, {
      cwd: process.cwd(),
      encoding: 'utf-8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Timeout: kill after BINARY_TIMEOUT_MS
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      child.killed || child.kill('SIGTERM');
      // On Windows SIGTERM may not work, give OS a chance
      setTimeout(() => {
        child.killed || child.kill('SIGKILL');
      }, 5000).unref();
    }, BINARY_TIMEOUT_MS);
    timers.push(timeoutTimer);

    // Abort signal support
    let abortHandler;
    if (signal) {
      abortHandler = () => {
        killed = true;
        clearTimeout(timeoutTimer);
        child.killed || child.kill('SIGTERM');
        setTimeout(() => {
          child.killed || child.kill('SIGKILL');
        }, 3000).unref();
      };
      signal.addEventListener('abort', abortHandler, { once: true });
    }

    let outputLimitHit = false;

    // Stream stdout with memory cap
    child.stdout.on('data', (data) => {
      if (stdout.length < MAX_STDOUT_BYTES) {
        stdout += data;
      } else if (!killed) {
        killed = true;
        outputLimitHit = true;
        clearTimeout(timeoutTimer);
        child.kill('SIGTERM');
      }
    });

    // Stream stderr with memory cap
    child.stderr.on('data', (data) => {
      if (stderr.length < MAX_STDERR_BYTES) {
        stderr += data;
      }
    });

    // Cleanup on error
    child.on('error', (err) => {
      timers.forEach(clearTimeout);
      if (abortHandler && signal) {
        signal.removeEventListener('abort', abortHandler);
      }
      resolve({
        ok: false,
        stdout,
        stderr,
        error: err.message,
      });
    });

    // Resolve on exit
    child.on('close', (code) => {
      timers.forEach(clearTimeout);
      if (abortHandler && signal) {
        signal.removeEventListener('abort', abortHandler);
      }

      if (killed) {
        const msg = outputLimitHit
          ? 'Command output exceeded 10MB limit. Try running on a more specific directory.'
          : 'Command was cancelled';
        resolve({
          ok: false,
          stdout,
          stderr,
          error: msg,
        });
        return;
      }

      if (timedOut) {
        resolve({
          ok: false,
          stdout,
          stderr,
          error: 'Command timed out after ' + (BINARY_TIMEOUT_MS / 1000) + 's. Try on a smaller directory or use --filter flags.',
        });
        return;
      }

      if (code !== 0) {
        resolve({
          ok: false,
          stdout,
          stderr,
          error: stderr.trim() || 'Command failed with exit code ' + code,
        });
        return;
      }

      resolve({
        ok: true,
        stdout,
        stderr,
      });
    });

    // Don't let the timer keep the process alive
    timeoutTimer.unref();
  });
}

module.exports.runCommand = runCommand;
