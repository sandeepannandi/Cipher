const React = require('react');
const { Box, Text, useInput } = require('ink');

const MODELS = ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768', 'gemma2-9b-it'];

const COMMANDS = [
  { cmd: 'init',         desc: 'Index your codebase for analysis' },
  { cmd: 'init --force', desc: 'Force re-index' },
  { cmd: 'review',                          desc: 'Scan for OWASP Top 10 vulnerabilities' },
  { cmd: 'review --ai',                     desc: 'Review with AI-powered deep analysis' },
  { cmd: 'review --max-findings 10',        desc: 'Review (limit to top 10 findings)' },
  { cmd: 'review --min-severity high',      desc: 'Review (only high+ severity)' },
  { cmd: 'review --min-confidence medium',  desc: 'Review (only medium+ confidence)' },
  { cmd: 'review --format sarif',           desc: 'Review → SARIF JSON output' },
  { cmd: 'review --format json',            desc: 'Review → machine-readable JSON' },
  { cmd: 'review --output file.json',       desc: 'Write review output to file' },
  { cmd: 'deps',         desc: 'Check dependency vulnerabilities' },
  { cmd: 'deps --online',desc: 'Check deps with OSV.dev API' },
  { cmd: 'deps --fail-on high', desc: 'Deps check, fail on high+' },
  { cmd: 'secrets',      desc: 'Scan for leaked credentials' },
  { cmd: 'secrets --fail-on high', desc: 'Secrets scan, fail on high+' },
  { cmd: 'ask',          desc: 'Ask a security question (uses AI)' },
  { cmd: 'report',       desc: 'Generate security report' },
  { cmd: 'fix --list',   desc: 'List fixable findings' },
  { cmd: 'fix --dry-run',desc: 'Preview fixes without applying' },
  { cmd: 'attack',       desc: 'Discover attack chains' },
  { cmd: 'ci',                                desc: 'Run all 5 scans (review+secrets+deps+zeroday+attack)' },
  { cmd: 'ci --format json',                  desc: 'CI → machine-readable JSON' },
  { cmd: 'ci --format json --output ci.json', desc: 'CI → JSON written to file' },
  { cmd: 'ci --fail-on critical',             desc: 'CI: fail only on critical findings' },
  { cmd: 'config',       desc: 'Show or set configuration' },
  { cmd: 'zeroday',                               desc: '3-layer zero-day anomaly detection' },
  { cmd: 'zeroday --ai',                           desc: 'Zero-day + AI-powered analysis' },
  { cmd: 'zeroday --anomaly-only',                 desc: 'Zero-day: anomaly layer only' },
  { cmd: 'zeroday --no-flow',                      desc: 'Zero-day: skip taint flow analysis' },
  { cmd: 'zeroday --format json',                  desc: 'Zero-day → JSON output' },  { cmd: 'zeroday --format sarif',                  desc: 'Zero-day → SARIF JSON output' },
  { cmd: 'sbom',                                       desc: 'Generate CycloneDX SBOM' },
  { cmd: 'sbom --format spdx',                         desc: 'Generate SPDX SBOM' },
  { cmd: 'sbom --output bom.json',                     desc: 'Write SBOM to file' },
  { cmd: '---',          desc: '---' },
  { cmd: 'model',        desc: 'Show or switch AI model' },
  ...MODELS.map((m) => ({ cmd: 'model ' + m, desc: 'Switch to ' + m })),
  { cmd: 'status',       desc: 'Show index and API key status' },
  { cmd: '---',          desc: '---' },
  { cmd: 'clear',        desc: 'Clear messages' },
  { cmd: 'exit',         desc: 'Exit the TUI' },
];

const MAX_VISIBLE = 10;

function CommandPalette({ onSelect, onClose }) {
  const [selectedIdx, setSelectedIdx] = React.useState(0);
  const [search, setSearch] = React.useState('');
  const [scrollOffset, setScrollOffset] = React.useState(0);

  const filtered = COMMANDS.filter((c) => c.cmd !== '---' && c.cmd.toLowerCase().includes(search.toLowerCase()));
  const maxOffset = Math.max(0, filtered.length - MAX_VISIBLE);

  useInput((input, key) => {
    if (key.escape) { onClose(); return; }
    if (key.return && filtered[selectedIdx]) { onSelect(filtered[selectedIdx].cmd); return; }
    if (key.upArrow) {
      const newIdx = Math.max(0, selectedIdx - 1);
      setSelectedIdx(newIdx);
      if (newIdx < scrollOffset) setScrollOffset(newIdx);
      return;
    }
    if (key.downArrow) {
      const newIdx = Math.min(filtered.length - 1, selectedIdx + 1);
      setSelectedIdx(newIdx);
      if (newIdx >= scrollOffset + MAX_VISIBLE) setScrollOffset(newIdx - MAX_VISIBLE + 1);
      return;
    }
    if (key.backspace || key.delete) { setSearch((p) => p.slice(0, -1)); setSelectedIdx(0); setScrollOffset(0); return; }
    if (input.length >= 1) { setSearch((p) => p + input); setSelectedIdx(0); setScrollOffset(0); }
  });

  const visible = filtered.slice(scrollOffset, scrollOffset + MAX_VISIBLE);

  return React.createElement(Box, {
    flexDirection: 'column', borderStyle: 'round', borderColor: 'yellow',
    padding: 1, marginLeft: 2, marginRight: 2, marginTop: 1,
    height: MAX_VISIBLE + 5,
  },
    React.createElement(Box, { marginBottom: 1 },
      React.createElement(Text, { bold: true, color: 'yellow' }, ' Command Palette ')),
    React.createElement(Box, { borderStyle: 'single', borderColor: 'green', paddingLeft: 1, marginBottom: 1 },
      React.createElement(Text, { color: 'green' }, '> '),
      React.createElement(Text, { color: search ? 'yellow' : 'green' }, search || 'Type to filter...')),
    scrollOffset > 0 && React.createElement(Box, {},
      React.createElement(Text, { color: 'green', dim: true }, '  ↑ ' + scrollOffset + ' more')),
    ...visible.map((cmd, i) => {
      const globalIdx = scrollOffset + i;
      return React.createElement(Box, {
        key: cmd.cmd, flexDirection: 'row',
        backgroundColor: globalIdx === selectedIdx ? 'green' : undefined,
      },
        React.createElement(Box, { width: 24 },
          React.createElement(Text, { color: 'yellow', bold: globalIdx === selectedIdx }, '  ' + cmd.cmd)),
        React.createElement(Text, { color: globalIdx === selectedIdx ? 'yellow' : 'white' }, cmd.desc));
    }),
    scrollOffset < maxOffset && React.createElement(Box, {},
      React.createElement(Text, { color: 'green', dim: true }, '  ↓ ' + (filtered.length - scrollOffset - MAX_VISIBLE) + ' more')),
    React.createElement(Box, { marginTop: 0 },
      React.createElement(Text, { color: 'green' }, '↑↓ Navigate  Enter Select  Esc Close')));
}

module.exports.CommandPalette = CommandPalette;
