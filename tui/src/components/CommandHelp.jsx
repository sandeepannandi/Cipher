const React = require('react');
const { Box, Text, useInput } = require('ink');

const COMMANDS = [
  { cmd: '/init',         desc: 'Index your codebase for analysis' },
  { cmd: '/init --force', desc: 'Force re-index' },
  { cmd: '/review',                          desc: 'Scan for OWASP Top 10 vulnerabilities' },
  { cmd: '/review --ai',                     desc: 'Review with AI-powered deep analysis' },
  { cmd: '/review --max-findings 10',        desc: 'Limit review to top 10 findings' },
  { cmd: '/review --min-severity high',      desc: 'Show only high+ severity findings' },
  { cmd: '/review --min-confidence medium',  desc: 'Show only medium+ confidence findings' },
  { cmd: '/review --format sarif',           desc: 'Review with SARIF output' },
  { cmd: '/deps',         desc: 'Check dependency vulnerabilities' },
  { cmd: '/deps --online',desc: 'Check deps with OSV.dev API' },
  { cmd: '/deps --fail-on high', desc: 'Deps check, exit 1 on high+' },
  { cmd: '/secrets',      desc: 'Scan for leaked credentials' },
  { cmd: '/secrets --fail-on high', desc: 'Secrets scan, exit 1 on high+' },
  { cmd: '/ask',          desc: 'Ask a security question (uses AI)' },
  { cmd: '/report',       desc: 'Generate security report' },
  { cmd: '/fix --list',   desc: 'List fixable findings' },
  { cmd: '/fix --dry-run',desc: 'Preview fixes without applying' },
  { cmd: '/attack',       desc: 'Discover attack chains' },
  { cmd: '/ci',           desc: 'Run all scans (CI mode)' },
  { cmd: '/config',       desc: 'Show or set configuration' },
  { cmd: '/model',        desc: 'Show or switch AI model' },
  { cmd: '/status',       desc: 'Show index and API key status' },
  { cmd: '/clear',        desc: 'Clear messages' },
  { cmd: '/exit',         desc: 'Exit the TUI' },
];

const MAX_VISIBLE = 12;

function CommandHelp({ onClose }) {
  const [scrollOffset, setScrollOffset] = React.useState(0);
  const maxOffset = Math.max(0, COMMANDS.length - MAX_VISIBLE);

  useInput((_input, key) => {
    if (key.escape) onClose();
    if (key.upArrow) setScrollOffset((p) => Math.max(0, p - 1));
    if (key.downArrow) setScrollOffset((p) => Math.min(maxOffset, p + 1));
    if (key.pageUp) setScrollOffset((p) => Math.max(0, p - MAX_VISIBLE));
    if (key.pageDown) setScrollOffset((p) => Math.min(maxOffset, p + MAX_VISIBLE));
  });

  const visible = COMMANDS.slice(scrollOffset, scrollOffset + MAX_VISIBLE);

  return React.createElement(Box, {
    flexDirection: 'column', borderStyle: 'round', borderColor: 'yellow',
    padding: 1, marginLeft: 2, marginRight: 2, marginTop: 1,
    height: MAX_VISIBLE + 5,
  },
    React.createElement(Box, { marginBottom: 0 },
      React.createElement(Text, { bold: true, color: 'yellow' }, ' Commands (Esc to close) ')),
    scrollOffset > 0 && React.createElement(Box, {},
      React.createElement(Text, { color: 'green', dim: true }, '  ↑ ' + scrollOffset + ' more' )),
    ...visible.map((cmd) =>
      React.createElement(Box, { key: cmd.cmd, flexDirection: 'row' },
        React.createElement(Box, { width: 24 },
          React.createElement(Text, { color: 'yellow', bold: true }, '  ' + cmd.cmd)),
        React.createElement(Text, { color: 'white' }, cmd.desc))),
    scrollOffset < maxOffset && React.createElement(Box, {},
      React.createElement(Text, { color: 'green', dim: true }, '  ↓ ' + (COMMANDS.length - scrollOffset - MAX_VISIBLE) + ' more')),
    React.createElement(Box, { marginTop: 0 },
      React.createElement(Text, { color: 'green' }, '  ↑↓ scroll  Esc=close  Ctrl+K=palette  up/down=history')));
}

module.exports.CommandHelp = CommandHelp;
