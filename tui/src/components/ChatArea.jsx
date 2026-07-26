const React = require('react');
const { Box, Text, useInput } = require('ink');
const { Message } = require('./Message');

const MAX_VISIBLE_MESSAGES = 100;

function ChatArea({ messages, isRunning }) {
  const [scrollOffset, setScrollOffset] = React.useState(0);
  const containerRef = React.useRef(null);

  // Auto-scroll to bottom on new messages (unless user scrolled up)
  React.useEffect(() => {
    if (scrollOffset === 0) {
      // Already at bottom
    }
    // If at bottom, stay at bottom
    setScrollOffset(0);
  }, [messages.length]);

  // Keyboard scrolling
  useInput((input, key) => {
    if (key.upArrow) {
      setScrollOffset((prev) => Math.min(prev + 1, Math.max(0, messages.length - 10)));
    }
    if (key.downArrow) {
      setScrollOffset((prev) => Math.max(0, prev - 1));
    }
    if (key.pageUp) {
      setScrollOffset((prev) => Math.min(prev + 10, Math.max(0, messages.length - 10)));
    }
    if (key.pageDown) {
      setScrollOffset((prev) => Math.max(0, prev - 10));
    }
  });

  // Show only a window of messages
  const visibleMessages = messages.slice(-MAX_VISIBLE_MESSAGES);
  const startIndex = Math.max(0, visibleMessages.length - 10 - scrollOffset);
  const endIndex = Math.min(visibleMessages.length, startIndex + 10);
  const displayMessages = visibleMessages.slice(startIndex, endIndex);

  return React.createElement(Box, {
    flexDirection: 'column',
    flexGrow: 1,
    overflowY: 'auto',
    paddingLeft: 1,
    paddingRight: 1,
    paddingTop: 1,
  },
    // Messages
    ...displayMessages.map((msg) =>
      React.createElement(Message, {
        key: msg.id,
        message: msg,
      })
    ),

    // Loading indicator
    isRunning && React.createElement(Box, { marginTop: 1 },
      React.createElement(Text, { color: 'yellow' },
        '⏳  Running...'
      )
    ),

    // Spacer for scrolling
    React.createElement(Box, { height: 1 })
  );
}

module.exports.ChatArea = ChatArea;
