const React = require('react');
const { render, Box, Text, useApp, useInput } = require('ink');
const { ChatArea } = require('./components/ChatArea');
const { InputBox } = require('./components/InputBox');
const { StatusBar } = require('./components/StatusBar');
const { CommandHelp } = require('./components/CommandHelp');
const { CommandPalette } = require('./components/CommandPalette');
const { runCommand } = require('./commands/runner');

const MODELS = ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768', 'gemma2-9b-it'];

const COMMAND_LIST = ['init', 'review', 'deps', 'secrets', 'ask', 'report', 'fix', 'attack', 'status', 'ci', 'config', 'zeroday', 'sbom'];

function isQuestion(text) {
  const qWords = ['what', 'how', 'why', 'is', 'can', 'does', 'are', 'do', 'will',
    'would', 'could', 'should', 'has', 'have', 'did', 'was', 'were',
    'find', 'show', 'list', 'tell', 'explain', 'describe', 'review'];
  const lower = text.toLowerCase().trim();
  if (lower.endsWith('?')) return true;
  return qWords.some((w) => lower.startsWith(w));
}

function App() {
  const { exit } = useApp();
  const [messages, setMessages] = React.useState([{
    id: 'welcome',
    type: 'system',
    text: '',
  }]);
  const [input, setInput] = React.useState('');
  const [isRunning, setIsRunning] = React.useState(false);
  const [showHelp, setShowHelp] = React.useState(false);
  const [showPalette, setShowPalette] = React.useState(false);
  const [showAskPrompt, setShowAskPrompt] = React.useState(false);
  const [status, setStatus] = React.useState({ index: 'unknown', apiKey: 'unknown' });
  const [modelIdx, setModelIdx] = React.useState(0);
  const [history, setHistory] = React.useState([]);
  const [historyIdx, setHistoryIdx] = React.useState(-1);
  const abortRef = React.useRef(null);

  // Esc handling at app level: close overlays OR cancel running command
  useInput((_input, key) => {
    if (key.ctrl && _input === 'k') { setShowHelp(false); setShowPalette((p) => !p); return; }
    if (key.ctrl && _input === 'l') { setMessages([{ id: 'welcome', type: 'system', text: '' }]); return; }
    if (key.ctrl && _input === 'm') { setModelIdx((p) => (p + 1) % MODELS.length); return; }
    if (key.escape) {
      // Close overlays first
      if (showHelp) { setShowHelp(false); return; }
      if (showPalette) { setShowPalette(false); return; }
      if (showAskPrompt) { setShowAskPrompt(false); return; }
      // Cancel running command
      if (isRunning && abortRef.current) {
        abortRef.current.abort();
        addMessage('system', 'Command cancelled.');
        setIsRunning(false);
        return;
      }
    }
  });

  // Command history navigation: handled in InputBox via callbacks
  function navigateHistory(direction) {
    if (history.length === 0) return;
    if (direction === 'up') {
      const newIdx = historyIdx < history.length - 1 ? historyIdx + 1 : history.length - 1;
      setHistoryIdx(newIdx);
      setInput(history[history.length - 1 - newIdx]);
    } else if (direction === 'down') {
      const newIdx = historyIdx - 1;
      if (newIdx < 0) {
        setHistoryIdx(-1);
        setInput('');
      } else {
        setHistoryIdx(newIdx);
        setInput(history[history.length - 1 - newIdx]);
      }
    }
  }

  React.useEffect(() => {
    runCommand(['status']).then((r) => {
      if (r.ok) {
        const out = r.stdout.toLowerCase();
        setStatus({
          index: out.includes('indexed') ? 'indexed' : 'not indexed',
          apiKey: out.includes('groq_api_key') || out.includes('api key') ? 'set' : 'unknown',
        });
      }
    }).catch(() => {});
  }, []);

  function addMessage(type, text) {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    setMessages((prev) => [...prev, { id, type, text }]);
  }

  async function handleSubmit(value) {
    const trimmed = value.trim();
    if (!trimmed || isRunning) return;

    // Add to history
    setHistory((prev) => [...prev, trimmed]);

    if (showAskPrompt) {
      setShowAskPrompt(false);
      setInput('');
      await handleCommand('/ask ' + trimmed);
      return;
    }
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

  function handleInputChange(val) { setInput(val); }

  async function handleCommand(input) {
    const parts = input.slice(1).trim().split(/\s+/);
    const command = parts[0]?.toLowerCase();
    const cmdArgs = parts.slice(1);

    switch (command) {
      case 'help': case 'h': setShowHelp(true); return;
      case 'exit': case 'quit': case 'q': exit(); return;
      case 'clear': case 'cls': setMessages([{ id: 'welcome', type: 'system', text: '' }]); return;
      case 'model':
        if (cmdArgs.length > 0) {
          const idx = MODELS.indexOf(cmdArgs[0]);
          if (idx >= 0) { setModelIdx(idx); addMessage('result', 'Model switched to: ' + MODELS[idx]); }
          else { addMessage('error', 'Unknown model. Available: ' + MODELS.join(', ')); }
        } else {
          addMessage('result', 'Current model: ' + MODELS[modelIdx] + '\nSwitch: /model <name>\nAvailable: ' + MODELS.join(', '));
        }
        return;
      case 'ask':
        if (cmdArgs.length === 0) {
          setShowAskPrompt(true);
          addMessage('system', 'Type your question and press Enter, or press Esc to cancel.');
          return;
        }
        break;
    }

    addMessage('user', input);
    const isKnown = COMMAND_LIST.includes(command);
    if (!isKnown) {
      addMessage('error', 'Unknown command: /' + command + '\nRun /help for available commands.');
      return;
    }

    const labels = {
      init: 'Indexing project...', review: 'Running security review...', deps: 'Checking dependencies...',
      secrets: 'Scanning for secrets...', ask: 'Asking AI...', report: 'Generating report...',
      fix: 'Generating fix...', attack: 'Analyzing attack paths...', status: 'Checking status...',
      ci: 'Running all scans...', config: 'Configuring...',
      zeroday: 'Running zero-day analysis...',
      sbom: 'Generating SBOM...',
    };
    addMessage('command', labels[command] || 'Running ' + command + '...');
    setIsRunning(true);
    setHistoryIdx(-1);

    // Create AbortController for this command
    const abortController = new AbortController();
    abortRef.current = abortController;

    const result = await runCommand([command, ...cmdArgs], abortController.signal);
    setIsRunning(false);
    abortRef.current = null;

    if (result.ok) {
      addMessage('result', result.stdout.trim() || result.stderr.trim() || '(no output)');
    } else {
      // Show stdout output first (contains scan results)
      // Only show error separately if it's not already in the stdout
      const outMsg = result.stdout.trim();
      const errMsg = result.stderr.trim() || result.error || 'Command failed';
      if (outMsg) {
        addMessage('result', outMsg);
        // Only add error message if it's not already visible in stdout
        if (!outMsg.includes(errMsg.replace(/[✗×✕✖]\s*/g, '').trim())) {
          addMessage('error', errMsg);
        }
      } else {
        addMessage('error', errMsg);
      }
    }
  }

  return React.createElement(Box, { flexDirection: 'column', height: '100%', width: '100%' },
    React.createElement(ChatArea, { messages, isRunning, model: MODELS[modelIdx], showAskPrompt }),
    showHelp && React.createElement(CommandHelp, { onClose: () => setShowHelp(false) }),
    showPalette && React.createElement(CommandPalette, {
      onSelect: (cmd) => {
        setShowPalette(false);
        if (cmd === 'exit') { exit(); return; }
        if (cmd === 'clear') { setMessages([{ id: 'welcome', type: 'system', text: '' }]); return; }
        if (cmd.startsWith('model ')) {
          const m = cmd.slice(6);
          const idx = MODELS.indexOf(m);
          if (idx >= 0) setModelIdx(idx);
          return;
        }
        handleSubmit('/' + cmd);
      },
      onClose: () => setShowPalette(false),
    }),
    React.createElement(InputBox, {
      value: input, onChange: handleInputChange, onSubmit: handleSubmit,
      isRunning, showAskPrompt, onNavigateHistory: navigateHistory,
    }),
    React.createElement(StatusBar, { status, model: MODELS[modelIdx], isRunning, messageCount: messages.length }),
  );
}

const { waitUntilExit } = render(React.createElement(App));
process.on('SIGINT', () => process.exit(0));
waitUntilExit().catch(() => {});
