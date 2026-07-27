const React = require('react');
const { Box, Text, useInput } = require('ink');
const { Message } = require('./Message');

function ChatArea({ messages, isRunning, model }) {
  const [scrollOffset, setScrollOffset] = React.useState(0);

  React.useEffect(() => { setScrollOffset(0); }, [messages.length]);

  useInput((_input, key) => {
    if (key.upArrow) setScrollOffset((p) => Math.min(p + 1, Math.max(0, messages.length - 10)));
    if (key.downArrow) setScrollOffset((p) => Math.max(0, p - 1));
    if (key.pageUp) setScrollOffset((p) => Math.min(p + 10, Math.max(0, messages.length - 10)));
    if (key.pageDown) setScrollOffset((p) => Math.max(0, p - 10));
  });

  const visible = messages.filter((m) => m.id !== 'welcome' || m.text);
  const showWelcome = messages.length === 1 && messages[0].id === 'welcome' && !messages[0].text;
  const start = Math.max(0, visible.length - 10 - scrollOffset);
  const end = Math.min(visible.length, start + 10);
  const display = visible.slice(start, end);
  const hasMore = visible.length > 10 && scrollOffset > 0;

  if (showWelcome) {
    return React.createElement(Box, {
      flexDirection: 'column', flexGrow: 1,
      alignItems: 'center', justifyContent: 'center',
    },
      React.createElement(Box, { marginBottom: 1 },
        React.createElement(Text, { bold: true, color: 'yellow', wrap: 'wrap' }, [
          '  ___ ___ ___ ___ ___ ___ ___  ',
          ' / __| _ \\_ _| _ \\ __| _ \\ ___|',
          '| (__|  _/| ||  _/ _||   / -_)',
          ' \\___|_| |___|_| |___|_|_\\___|',
        ].join('\n'))),
      React.createElement(Text, { bold: true, color: 'yellow' }, ' AI Security Engineer'),
      React.createElement(Text, { color: 'green', dim: true }, '/help for commands  Ctrl+K for palette'),
      React.createElement(Text, { color: 'green', dim: true }, 'model: ' + model),
    );
  }

  return React.createElement(Box, { flexDirection: 'column', flexGrow: 1, paddingLeft: 1, paddingRight: 1, paddingTop: 1 },
    hasMore && React.createElement(Box, { marginBottom: 1 },
      React.createElement(Text, { color: 'green', dim: true }, 'up arrow for older messages')),
    ...display.map((msg) => React.createElement(Message, { key: msg.id, message: msg })),
    isRunning && React.createElement(Box, { marginTop: 1, marginLeft: 2 },
      React.createElement(Text, { color: 'yellow' }, 'running...')),
    React.createElement(Box, { height: 1 }));
}

module.exports.ChatArea = ChatArea;
