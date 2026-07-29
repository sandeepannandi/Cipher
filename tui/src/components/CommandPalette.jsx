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
  { cmd: 'review --format sarif',           desc: 'Review with SARIF output' },
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
  { cmd: 'ci',           desc: 'Run all scans (CI mode)' },
  { cmd: 'config',       desc: 'Show or set configuration' },
  { cmd: '---',          desc: '---' },
  { cmd: 'model',        desc: 'Show or switch AI model' },
  ...MODELS.map((m) => ({ cmd: 'model ' + m, desc: 'Switch to ' + m })),
  { cmd: 'status',       desc: 'Show index and API key status' },
  { cmd: '---',          desc: '---' },
  { cmd: 'clear',        desc: 'Clear messages' },
  { cmd: 'exit',         desc: 'Exit the TUI' },
];

function CommandPalette({ onSelect, onClose }) {
  const [selectedIdx, setSelectedIdx] = React.useState(0);
  const [search, setSearch] = React.useState('');

  const filtered = COMMANDS.filter((c) => c.cmd !== '---' && c.cmd.toLowerCase().includes(search.toLowerCase()));

  useInput((input, key) => {
    if (key.escape) { onClose(); return; }
    if (key.return && filtered[selectedIdx]) { onSelect(filtered[selectedIdx].cmd); return; }
    if (key.upArrow) { setSelectedIdx((p) => Math.max(0, p - 1)); return; }
    if (key.downArrow) { setSelectedIdx((p) => Math.min(filtered.length - 1, p + 1)); return; }
    if (key.backspace || key.delete) { setSearch((p) => p.slice(0, -1)); return; }
    if (input.length >= 1) { setSearch((p) => p + input); setSelectedIdx(0); }
  });

  return React.createElement(Box, {
    flexDirection: 'column', borderStyle: 'round', borderColor: 'yellow',
    padding: 1, marginLeft: 2, marginRight: 2, marginTop: 1,
  },
    React.createElement(Box, { marginBottom: 1 },
      React.createElement(Text, { bold: true, color: 'yellow' }, ' Command Palette ')),
    React.createElement(Box, { borderStyle: 'single', borderColor: 'green', paddingLeft: 1, marginBottom: 1 },
      React.createElement(Text, { color: 'green' }, '> '),
      React.createElement(Text, { color: search ? 'yellow' : 'green' }, search || 'Type to filter...')),
    ...filtered.map((cmd, i) =>
      React.createElement(Box, {
        key: cmd.cmd, flexDirection: 'row',
        backgroundColor: i === selectedIdx ? 'green' : undefined,
      },
        React.createElement(Box, { width: 24 },
          React.createElement(Text, { color: 'yellow', bold: i === selectedIdx }, '  ' + cmd.cmd)),
        React.createElement(Text, { color: i === selectedIdx ? 'yellow' : 'white' }, cmd.desc))),
    React.createElement(Box, { marginTop: 1 },
      React.createElement(Text, { color: 'green' }, 'up/down Navigate  Enter Select  Esc Close')));
}

module.exports.CommandPalette = CommandPalette;
