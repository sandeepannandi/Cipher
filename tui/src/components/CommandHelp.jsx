const React = require('react');
const { Box, Text, useInput } = require('ink');

const COMMANDS = [
  { cmd: '/init',         desc: 'Index your codebase for analysis' },
  { cmd: '/init --force', desc: 'Force re-index' },
  { cmd: '/review',       desc: 'Scan for OWASP Top 10 vulnerabilities' },
  { cmd: '/review --ai',  desc: 'Review with AI-powered deep analysis' },
  { cmd: '/deps',         desc: 'Check dependency vulnerabilities' },
  { cmd: '/deps --online',desc: 'Check deps with OSV.dev API' },
  { cmd: '/secrets',      desc: 'Scan for leaked credentials' },
  { cmd: '/ask',          desc: 'Ask a security question (uses AI)' },
  { cmd: '/report',       desc: 'Generate security report' },
  { cmd: '/fix --list',   desc: 'List fixable findings' },
  { cmd: '/attack',       desc: 'Discover attack chains' },
  { cmd: '/model',        desc: 'Show or switch AI model' },
  { cmd: '/status',       desc: 'Show index and API key status' },
  { cmd: '/clear',        desc: 'Clear messages' },
  { cmd: '/exit',         desc: 'Exit the TUI' },
];

function CommandHelp({ onClose }) {
  useInput((_input, key) => { if (key.escape) onClose(); });

  return React.createElement(Box, {
    flexDirection: 'column', borderStyle: 'round', borderColor: 'yellow',
    padding: 1, marginLeft: 2, marginRight: 2, marginTop: 1,
  },
    React.createElement(Box, { marginBottom: 1 },
      React.createElement(Text, { bold: true, color: 'yellow' }, ' Commands ')),
    ...COMMANDS.map((cmd) =>
      React.createElement(Box, { key: cmd.cmd, flexDirection: 'row', marginBottom: 0 },
        React.createElement(Box, { width: 22 },
          React.createElement(Text, { color: 'yellow', bold: true }, '  ' + cmd.cmd)),
        React.createElement(Text, { color: 'white' }, cmd.desc))),
    React.createElement(Box, { marginTop: 1 },
      React.createElement(Text, { color: 'green' }, '  Esc to close  Ctrl+K for palette')));
}

module.exports.CommandHelp = CommandHelp;
