const React = require('react');
const { Box, Text, useInput } = require('ink');

function InputBox({ value, onChange, onSubmit, isRunning }) {
  useInput((input, key) => {
    if (isRunning) return;

    if (key.return) {
      onSubmit(value);
      return;
    }

    if (key.backspace || key.delete) {
      onChange(value.slice(0, -1));
      return;
    }

    // Ignore control characters and function keys
    if (input.length === 1 || (input.length > 1 && !key.ctrl)) {
      onChange(value + input);
    }
  });

  // Detect if this looks like a question
  const isLikelyQuestion = value.trim().length > 0 && !value.trim().startsWith('/');

  return React.createElement(Box, {
    borderStyle: 'round',
    borderColor: isRunning ? 'yellow' : 'cyan',
    marginTop: 1,
    marginLeft: 1,
    marginRight: 1,
    paddingLeft: 1,
  },
    React.createElement(Text, { bold: true, color: 'cyan' }, '> '),
    React.createElement(Text, { color: isRunning ? 'yellow' : 'white' },
      value || (isRunning ? '' : 'Type /help or ask a question...')
    ),
    !isRunning && React.createElement(Text, { color: 'gray' }, ' ')
  );
}

module.exports.InputBox = InputBox;
