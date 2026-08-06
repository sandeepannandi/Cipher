const { spawn } = require('child_process');
const { findBinaryPath } = require('../utils/binary');

const BINARY_TIMEOUT_MS = 120_000; // 2 minutes (reduced from 5)
// Autonomous pentest agent runs can take several minutes (LLM turns + tool
// scans), so give `pentest` a much larger budget than the default.
const PENTEST_TIMEOUT_MS = 600_000; // 10 minutes
const MAX_STDOUT_BYTES = 10 * 1024 * 1024; // 10MB max buffered output
const MAX_STDERR_BYTES = 5 * 1024 * 1024;  // 5MB max buffered stderr

/**
 * Command timeout in ms: `pentest` gets a much larger budget than other
 * commands (agent loop runs many LLM turns + tool scans).
 */
function commandTimeoutMs(args) {
  return args[0] === 'pentest' ? PENTEST_TIMEOUT_MS : BINARY_TIMEOUT_MS;
}

// Active AI model selected in the TUI, forwarded to the Rust binary via
// CIPHER_AI_MODEL (the provider-agnostic override every command honors).
let currentModel = null;

/**
 * Set the AI model override for all subsequent commands (null = provider default).
 * @param {string|null} model
 */
function setModel(model) {
  currentModel = model || null;
}

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
    const timeoutMs = commandTimeoutMs(args);

    // If useWSL is true, prefix the command with 'wsl'
    const command = result.useWSL ? 'wsl' : result.path;
    const cmdArgs = result.useWSL ? [result.path, ...args] : args;

    const env = { ...process.env };
    if (currentModel) env.CIPHER_AI_MODEL = currentModel;

    const child = spawn(command, cmdArgs, {
      cwd: process.cwd(),
      encoding: 'utf-8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });

    // Timeout: kill after timeoutMs (longer for pentest)
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      child.killed || child.kill('SIGTERM');
      // On Windows SIGTERM may not work, give OS a chance
      setTimeout(() => {
        child.killed || child.kill('SIGKILL');
      }, 5000).unref();
    }, timeoutMs);
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
          error: 'Command timed out after ' + (timeoutMs / 1000) + 's. Try on a smaller directory or use --filter flags.',
        });
        return;
      }

      if (code !== 0) {
        // Some commands (e.g., ci) write failure messages to stdout, not stderr.
        // Extract meaningful error from the last relevant lines of stdout.
        const stderrMsg = stderr.trim();
        // Look for error-like lines in stdout (lines starting with ✗, Error, error, etc.)
        const stdoutLines = stdout.trim().split('\n').filter(l => l.trim());
        const errorLine = stdoutLines.reverse().find(l =>
          /[✗×✕✖]\s/.test(l) || /^\s*error:/i.test(l) || /check failed/i.test(l) || /FAILED/i.test(l)
        );
        const errorMsg = stderrMsg || (errorLine ? errorLine.trim() : '') || 'Command failed with exit code ' + code;
        resolve({
          ok: false,
          stdout,
          stderr,
          error: errorMsg,
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
module.exports.setModel = setModel;
