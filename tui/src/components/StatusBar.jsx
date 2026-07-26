const React = require('react');
const { Box, Text } = require('ink');

const STATUS_COLORS = {
  indexed: { label: '✅ Indexed', color: 'green' },
  'not indexed': { label: '📭 Not indexed', color: 'red' },
  set: { label: '✅ Key set', color: 'green' },
  missing: { label: '❌ No key', color: 'red' },
  unknown: { label: '⋯ Unknown', color: 'gray' },
  true: { label: '✅ Ready', color: 'green' },
  false: { label: '❌ Not ready', color: 'red' },
};

function StatusBar({ status, isRunning, messageCount }) {
  const indexStatus = STATUS_COLORS[status.index] || STATUS_COLORS.unknown;
  const keyStatus = STATUS_COLORS[status.apiKey] || STATUS_COLORS.unknown;

  return React.createElement(Box, {
    borderStyle: 'single',
    borderColor: 'gray',
    marginTop: 0,
    paddingLeft: 1,
    paddingRight: 1,
  },
    // Index status
    React.createElement(Text, { color: indexStatus.color }, indexStatus.label),

    React.createElement(Text, { color: 'gray' }, ' │ '),

    // API key status
    React.createElement(Text, { color: keyStatus.color }, keyStatus.label),

    React.createElement(Text, { color: 'gray' }, ' │ '),

    // Running indicator
    React.createElement(Text, { color: isRunning ? 'yellow' : 'gray' },
      isRunning ? '⚡ Running...' : '○ Idle'
    ),

    React.createElement(Box, { flexGrow: 1 }),

    // Message count and version
    React.createElement(Text, { color: 'gray' },
      `${messageCount} msgs  │  v0.1.0`
    ),
  );
}

module.exports.StatusBar = StatusBar;
