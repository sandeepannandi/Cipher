#!/usr/bin/env node

/**
 * postinstall.js — Downloads the pre-built Rust binary for the current platform.
 *
 * Runs automatically after `npm install -g @cipher/security`.
 * Fetches the correct binary from GitHub Releases based on OS + arch.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

const REPO = 'sandeepannandi/Cipher';
const VERSION = 'v0.1.0';
const BINARY_NAME = 'cipher-ai';

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();

  const map = {
    'win32-x64':  BINARY_NAME + '-x86_64-pc-windows-msvc.exe',
    'linux-x64':  BINARY_NAME + '-x86_64-unknown-linux-gnu',
    'linux-arm64': BINARY_NAME + '-aarch64-unknown-linux-gnu',
    'darwin-x64': BINARY_NAME + '-x86_64-apple-darwin',
    'darwin-arm64': BINARY_NAME + '-aarch64-apple-darwin',
  };

  const key = platform + '-' + arch;
  return map[key] || null;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        file.close();
        fs.unlinkSync(dest);
        download(response.headers.location, dest).then(resolve).catch(reject);
        return;
      }
      if (response.statusCode !== 200) {
        file.close();
        fs.unlinkSync(dest);
        reject(new Error('HTTP ' + response.statusCode));
        return;
      }
      response.pipe(file);
      file.on('finish', () => {
        file.close();
        fs.chmodSync(dest, 0o755);
        resolve();
      });
    }).on('error', (err) => {
      file.close();
      try { fs.unlinkSync(dest); } catch {}
      reject(err);
    });
  });
}

async function main() {
  const binaryName = getPlatform();
  if (!binaryName) {
    console.warn('⚠ Unsupported platform: ' + os.platform() + '-' + os.arch() + '. Skipping binary download.');
    console.warn('  Build the binary manually: cargo build --release');
    return;
  }

  const installDir = path.join(os.homedir(), '.cipher-ai', 'bin');
  const destPath = path.join(installDir, os.platform() === 'win32' ? BINARY_NAME + '.exe' : BINARY_NAME);

  // Skip if already installed
  if (fs.existsSync(destPath)) {
    console.log('✓ CipherAI binary already installed at ' + destPath);
    return;
  }

  const url = 'https://github.com/' + REPO + '/releases/download/' + VERSION + '/' + binaryName;

  console.log('⬇ Downloading CipherAI binary for ' + os.platform() + '-' + os.arch() + '...');
  console.log('  ' + url);

  try {
    fs.mkdirSync(installDir, { recursive: true });
    await download(url, destPath);
    console.log('✓ Installed to ' + destPath);
    console.log('  Run "cipher-ai --help" to verify.');
  } catch (err) {
    console.warn('⚠ Failed to download binary: ' + err.message);
    console.warn('  Build it manually: cargo build --release');
  }
}

main();
