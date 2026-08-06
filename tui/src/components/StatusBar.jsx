const React = require('react');
const { Box, Text } = require('ink');

const indexColors = { indexed: 'green', 'not indexed': 'yellow', unknown: 'green' };
const keyColors = { set: 'green', missing: 'yellow', unknown: 'green' };
const providerColors = { groq: 'yellow', openai: 'green', anthropic: 'magenta' };

function StatusBar({ status, model, isRunning, messageCount }) {
  return React.createElement(Box, {
    flexDirection: 'row', borderStyle: 'single', borderColor: 'green',
    paddingLeft: 1, paddingRight: 1,
  },
    React.createElement(Text, { color: 'green' }, ' index '),
    React.createElement(Text, { color: indexColors[status.index] || 'green' }, status.index),
    React.createElement(Text, { color: 'green' }, ' | provider '),
    React.createElement(Text, { color: providerColors[status.provider] || 'white' }, status.provider || 'groq'),
    React.createElement(Text, { color: 'green' }, ' | api '),
    React.createElement(Text, { color: keyColors[status.apiKey] || 'green' }, status.apiKey),
    React.createElement(Box, { flexGrow: 1 }),
    React.createElement(Text, { color: isRunning ? 'yellow' : 'green' },
      isRunning ? 'running' : ''),
    isRunning && React.createElement(Text, { color: 'green' }, ' | '),
    React.createElement(Text, { color: 'green' }, ' model '),
    React.createElement(Text, { color: 'white' }, model),
    React.createElement(Text, { color: 'green' }, ' | '),
    React.createElement(Text, { color: 'green' }, messageCount + ' msgs'));
}

module.exports.StatusBar = StatusBar;
