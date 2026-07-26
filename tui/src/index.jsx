const React = require('react');
const { render, Box, useApp } = require('ink');

const { ChatArea } = require('./components/ChatArea');
const { InputBox } = require('./components/InputBox');
const { StatusBar } = require('./components/StatusBar');
const { CommandHelp } = require('./components/CommandHelp');
const { runCommand } = require('./commands/runner');

const VERSION = '0.1.0';

// ── Helpers ──

function isQuestion(text) {
  const qWords = [
    'what', 'how', 'why', 'is', 'can', 'does', 'are', 'do', 'will',
    'would', 'could', 'should', 'has', 'have', 'did', 'was', 'were',
    'find', 'show', 'list', 'tell', 'explain', 'describe', 'review',
  ];
  const lower = text.toLowerCase().trim();
  if (lower.endsWith('?')) return true;
  return qWords.some((w) => lower.startsWith(w));
}

// ── App ──

function App() {
  const { exit } = useApp();
  const [messages, setMessages] = React.useState([
    {
      id: 'welcome',
      type: 'system',
      text: '🛡  Cipher v' + VERSION + ' — AI Security Analysis\n\nType /help to see commands, or ask a security question.\n',
    },
  ]);
  const [input, setInput] = React.useState('');
  const [isRunning, setIsRunning] = React.useState(false);
  const [showHelp, setShowHelp] = React.useState(false);
  const [status, setStatus] = React.useState({ index: 'unknown', apiKey: 'unknown' });

  // Try to load status once on mount
  React.useEffect(() => {
    runCommand(['status'])
      .then((r) => {
        if (r.ok) {
          const out = r.stdout.toLowerCase();
          setStatus({
            index: out.includes('indexed') ? 'indexed' : 'not indexed',
            apiKey: out.includes('groq_api_key') || out.includes('api key') ? 'set' : 'unknown',
          });
        }
      })
      .catch(() => {});
  }, []);

  function addMessage(type, text) {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    setMessages((prev) => [...prev, { id, type, text }]);
  }

  async function handleSubmit(value) {
    const trimmed = value.trim();
    if (!trimmed || isRunning) return;
    setInput('');

    if (trimmed.startsWith('/')) {
      await handleCommand(trimmed);
    } else if (isQuestion(trimmed)) {
      addMessage('user', trimmed);
      await handleCommand('/ask ' + trimmed);
    } else {
      addMessage('error', 'Unknown input. Use / for commands or ask a question. Run /help.');
    }
  }

  async function handleCommand(input) {
    const parts = input.slice(1).trim().split(/\s+/);
    const command = parts[0]?.toLowerCase();
    const cmdArgs = parts.slice(1);

    // ── Built-in commands ──
    switch (command) {
      case 'help':
      case 'h':
        setShowHelp(true);
        return;
      case 'exit':
      case 'quit':
      case 'q':
        exit();
        return;
      case 'clear':
      case 'cls':
        setMessages([]);
        return;
    }

    // ── Rust binary commands ──
    addMessage('user', input);

    // Map of known Rust commands and their labels
    const isKnown = [
      'init', 'review', 'deps', 'secrets', 'ask',
      'report', 'fix', 'attack', 'status',
    ].includes(command);

    if (!isKnown) {
      addMessage('error', 'Unknown command: /' + command + '\nRun /help for available commands.');
      return;
    }

    const labels = {
      init:    'Indexing project...',
      review:  'Running security review...',
      deps:    'Checking dependencies...',
      secrets: 'Scanning for secrets...',
      ask:     'Asking AI...',
      report:  'Generating report...',
      fix:     'Generating fix...',
      attack:  'Analyzing attack paths...',
      status:  'Checking status...',
    };

    addMessage('command', labels[command] || 'Running ' + command + '...');
    setIsRunning(true);

    // Run the Rust binary with EXACTLY the args the user typed — no flags added
    const result = await runCommand([command, ...cmdArgs]);
    setIsRunning(false);

    if (result.ok) {
      const output = result.stdout.trim() || result.stderr.trim();
      addMessage('result', output || '(no output)');
    } else {
      const err = result.stderr.trim() || result.error || 'Command failed';
      addMessage('error', err);
    }
  }

  function handleCloseHelp() {
    setShowHelp(false);
  }

  // ── Render ──

  return React.createElement(Box, { flexDirection: 'column', height: '100%' },
    React.createElement(ChatArea, { messages, isRunning }),
    showHelp && React.createElement(CommandHelp, { onClose: handleCloseHelp }),
    React.createElement(InputBox, {
      value: input,
      onChange: setInput,
      onSubmit: handleSubmit,
      isRunning,
    }),
    React.createElement(StatusBar, { status, isRunning, messageCount: messages.length }),
  );
}

// ── Bootstrap ──

const { waitUntilExit } = render(React.createElement(App));

process.on('SIGINT', () => process.exit(0));
waitUntilExit().catch(() => {});
