const React = require('react');
const { Box, Text } = require('ink');

const TYPE_STYLES = {
  user: {
    prefix: '💬',
    color: 'cyan',
    bold: false,
  },
  command: {
    prefix: '⚡',
    color: 'yellow',
    bold: false,
  },
  result: {
    prefix: '',
    color: 'white',
    bold: false,
  },
  error: {
    prefix: '✖',
    color: 'red',
    bold: true,
  },
  system: {
    prefix: '',
    color: 'green',
    bold: false,
  },
};

function Message({ message }) {
  const style = TYPE_STYLES[message.type] || TYPE_STYLES.system;
  const lines = (message.text || '').split('\n');

  return React.createElement(Box, {
    flexDirection: 'column',
    marginTop: message.type === 'user' ? 1 : 0,
    marginBottom: message.type === 'result' ? 1 : 0,
  },
    // Prefix line for user/command/error messages
    (message.type === 'user' || message.type === 'command' || message.type === 'error') &&
      React.createElement(Box, { marginBottom: 1 },
        React.createElement(Text, { color: style.color, bold: style.bold },
          `${style.prefix}  ${message.type === 'user' ? 'You' : ''}`
        )
      ),

    // Content lines
    ...lines.map((line, i) => {
      // Empty lines
      if (!line.trim()) {
        return React.createElement(Box, { key: i }, React.createElement(Text, {}, ''));
      }

      // Indent result content (code/output)
      if (message.type === 'result' || message.type === 'error') {
        return React.createElement(Box, { key: i, paddingLeft: 2 },
          React.createElement(Text, { color: style.color, wrap: 'wrap' }, line)
        );
      }

      // System messages (no indent)
      if (message.type === 'system') {
        return React.createElement(Box, { key: i },
          React.createElement(Text, { color: style.color, wrap: 'wrap' }, line)
        );
      }

      // Everything else
      return React.createElement(Box, { key: i },
        React.createElement(Text, { color: style.color, wrap: 'wrap' }, line)
      );
    })
  );
}

module.exports.Message = Message;
