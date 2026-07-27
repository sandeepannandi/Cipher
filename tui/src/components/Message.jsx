const React = require('react');
const { Box, Text } = require('ink');

const TYPE_STYLES = {
  user:    { color: 'white', label: 'You' },
  command: { color: 'white', label: 'Command' },
  result:  { color: 'white', label: '' },
  error:   { color: 'red', label: 'Error' },
  system:  { color: 'green', label: '' },
};

function Message({ message }) {
  const style = TYPE_STYLES[message.type] || TYPE_STYLES.system;
  const lines = (message.text || '').split('\n');
  const isResult = message.type === 'result';
  const isUser = message.type === 'user';

  // User messages get a combined border box with label + text inside
  if (isUser) {
    return React.createElement(Box, { flexDirection: 'column', marginTop: 1 },
      React.createElement(Box, {
        flexDirection: 'column',
        borderStyle: 'round', borderColor: style.color,
        paddingLeft: 1, paddingRight: 1, paddingTop: 0, paddingBottom: 0,
      },
        React.createElement(Text, { color: style.color, bold: true }, style.label),
        ...lines.filter(l => l.trim()).map((line, i) =>
          React.createElement(Text, { key: i, color: style.color, wrap: 'wrap' }, line))));
  }

  // Result output: no label, no border
  if (isResult) {
    return React.createElement(Box, { flexDirection: 'column', marginTop: 0, marginBottom: 1 },
      ...lines.map((line, i) => {
        if (!line.trim()) return React.createElement(Box, { key: i, height: 1 });
        return React.createElement(Box, { key: i, paddingLeft: 2 },
          React.createElement(Text, { color: style.color, wrap: 'wrap' }, line));
      }));
  }

  // Command / Error / System: label prefix without border, then content
  return React.createElement(Box, { flexDirection: 'column', marginTop: 1 },
    style.label ? React.createElement(Box, { paddingLeft: 2, marginBottom: 0 },
      React.createElement(Text, { color: style.color, bold: true }, style.label)) : null,
    ...lines.map((line, i) => {
      if (!line.trim()) return React.createElement(Box, { key: i, height: 1 });
      return React.createElement(Box, { key: i, paddingLeft: 2 },
        React.createElement(Text, { color: style.color, wrap: 'wrap' }, line));
    }));
}

module.exports.Message = Message;
