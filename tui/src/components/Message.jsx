const React = require('react');
const { Box, Text } = require('ink');

const TYPE_STYLES = {
  user:    { color: 'white', label: 'You' },
  command: { color: 'yellow', label: 'Command' },
  result:  { color: 'white', label: '' },
  error:   { color: 'yellow', label: 'Error' },
  system:  { color: 'green', label: '' },
};

function Message({ message }) {
  const style = TYPE_STYLES[message.type] || TYPE_STYLES.system;
  const lines = (message.text || '').split('\n');
  const isCode = message.type === 'result' || message.type === 'error';

  return React.createElement(Box, { flexDirection: 'column', marginTop: message.type === 'result' ? 0 : 1, marginBottom: message.type === 'result' ? 1 : 0 },
    style.label ? React.createElement(Box, { paddingLeft: 1, marginBottom: 0 },
      React.createElement(Text, { color: style.color, bold: true }, style.label)) : null,
    ...lines.map((line, i) => {
      if (!line.trim()) return React.createElement(Box, { key: i, height: 1 });
      if (isCode) {
        return React.createElement(Box, { key: i, paddingLeft: 1 },
          React.createElement(Text, { color: style.color, wrap: 'wrap' }, line));
      }
      return React.createElement(Box, { key: i, paddingLeft: 2 },
        React.createElement(Text, { color: style.color, wrap: 'wrap', bold: i === 0 && message.type === 'user' }, line));
    }));
}

module.exports.Message = Message;
