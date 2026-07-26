const React = require('react');
const { Box, Text, useInput } = require('ink');

const COMMANDS = [
  { cmd: '/help',         desc: 'Show this help screen' },
  { cmd: '/init',         desc: 'Index your codebase for analysis' },
  { cmd: '/init --force', desc: 'Force re-index' },
  { cmd: '/review',       desc: 'Scan for OWASP Top 10 vulnerabilities' },
  { cmd: '/review --ai',  desc: 'Review with AI-powered deep analysis' },
  { cmd: '/deps',         desc: 'Check dependency vulnerabilities' },
  { cmd: '/deps --online',desc: 'Check deps with OSV.dev API' },
  { cmd: '/secrets',      desc: 'Scan for leaked credentials' },
  { cmd: '/ask <question>',desc: 'Ask a security question (uses AI)' },
  { cmd: '/report',       desc: 'Generate security report' },
  { cmd: '/fix --list',   desc: 'List fixable findings' },
  { cmd: '/attack',       desc: 'Discover attack chains' },
  { cmd: '/status',       desc: 'Show index and API key status' },
  { cmd: '/clear',        desc: 'Clear messages' },
  { cmd: '/exit',         desc: 'Exit the TUI' },
  { cmd: '? plain text',  desc: 'Ask a question naturally (no /)' },
];

function CommandHelp({ onClose }) {
  useInput((_input, key) => {
    if (key.escape || key.return || key.space) {
      onClose();
    }
  });

  return React.createElement(Box, {
    flexDirection: 'column',
    borderStyle: 'round',
    borderColor: 'cyan',
    padding: 1,
    marginLeft: 2,
    marginRight: 2,
    marginTop: 1,
  },
    React.createElement(Box, { marginBottom: 1 },
      React.createElement(Text, { bold: true, underline: true }, ' Cipher Commands ')
    ),

    ...COMMANDS.map((cmd) =>
      React.createElement(Box, { key: cmd.cmd, marginBottom: 1 },
        React.createElement(Box, { width: 22 },
          React.createElement(Text, { color: 'cyan', bold: true }, `  ${cmd.cmd}`)
        ),
        React.createElement(Text, {}, cmd.desc)
      )
    ),

    React.createElement(Box, { marginTop: 1 },
      React.createElement(Text, { color: 'gray' },
        'Press ESC or ENTER to close this help screen.'
      )
    )
  );
}

module.exports.CommandHelp = CommandHelp;
