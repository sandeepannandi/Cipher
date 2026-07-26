const React = require('react');
const { render, Box, useInput, useApp } = require('ink');

const { ChatArea } = require('./components/ChatArea');
const { InputBox } = require('./components/InputBox');
const { StatusBar } = require('./components/StatusBar');
const { CommandHelp } = require('./components/CommandHelp');
const { runCommand } = require('./commands/runner');

const VERSION = '0.1.0';

function App() {
  const { exit } = useApp();
  const [messages, setMessages] = React.useState([
    {
      id: 'welcome',
      type: 'system',
      text: [
        '🛡  Cipher v' + VERSION + ' — AI Security Analysis',
        '',
        'Type /help to see available commands, or ask a security question.',
        '',
      ].join('\n'),
    },
  ]);
  const [input, setInput] = React.useState('');
  const [isRunning, setIsRunning] = React.useState(false);
  const [showHelp, setShowHelp] = React.useState(false);
  const [status, setStatus] = React.useState({ index: 'unknown', apiKey: 'unknown' });

  // Load initial status on mount
  React.useEffect(() => {
    checkStatus().catch(() => {});
  }, []);

  async function checkStatus() {
    const result = await runCommand(['status', '--json'], { silent: true });
    if (result.ok && result.json) {
      setStatus({
        index: result.json.indexed ? 'indexed' : 'not indexed',
        apiKey: result.json.api_key ? 'set' : 'missing',
      });
    }
  }

  function addMessage(type, text, meta) {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    setMessages((prev) => [...prev, { id, type, text, ...meta }]);
  }

  async function handleSubmit(value) {
    const trimmed = value.trim();
    if (!trimmed || isRunning) return;

    setInput('');

    // Detect command or question
    if (trimmed.startsWith('/')) {
      await handleCommand(trimmed);
    } else if (isQuestion(trimmed)) {
      addMessage('user', trimmed);
      await handleCommand('/ask ' + trimmed);
    } else {
      addMessage('error', [
        'Unknown input. Start with / for commands or ask a question.',
        'Run /help to see available commands.',
      ].join('\n'));
    }
  }

  function isQuestion(text) {
    const questionWords = [
      'what', 'how', 'why', 'is', 'can', 'does', 'are', 'do', 'will',
      'would', 'could', 'should', 'has', 'have', 'did', 'was', 'were',
      'find', 'show', 'list', 'tell', 'explain', 'describe', 'review',
    ];
    const lower = text.toLowerCase().trim();
    if (lower.endsWith('?')) return true;
    return questionWords.some((w) => lower.startsWith(w));
  }

  async function handleCommand(input) {
    const parts = input.slice(1).trim().split(/\s+/);
    const command = parts[0]?.toLowerCase();
    const cmdArgs = parts.slice(1);

    // Built-in commands (don't need Rust binary)
    switch (command) {
      case 'help':
      case 'h': {
        setShowHelp(true);
        return;
      }
      case 'exit':
      case 'quit':
      case 'q': {
        exit();
        return;
      }
      case 'clear':
      case 'cls': {
        setMessages([]);
        return;
      }
    }

    // Rust binary commands
    addMessage('user', input);

    const binaryCommands = {
      init:      { args: cmdArgs,              label: 'Indexing project...' },
      review:    { args: cmdArgs,              label: 'Running security review...' },
      deps:      { args: cmdArgs,              label: 'Checking dependencies...' },
      secrets:   { args: cmdArgs,              label: 'Scanning for secrets...' },
      ask:       { args: cmdArgs,              label: 'Asking AI...' },
      report:    { args: ['--format', 'json'], label: 'Generating report...' },
      fix:       { args: cmdArgs,              label: 'Generating fix...' },
      attack:    { args: cmdArgs,              label: 'Analyzing attack paths...' },
      status:    { args: ['--json'],           label: 'Checking status...' },
    };

    if (!binaryCommands[command]) {
      addMessage('error', [
        'Unknown command: /' + command,
        'Run /help to see available commands.',
      ].join('\n'));
      return;
    }

    const { args: baseArgs, label } = binaryCommands[command];

    // Build final args: use a copy to avoid mutating the template
    // Add JSON flag for machine-readable output (if not already present)
    const args = baseArgs.includes('--json') || baseArgs.includes('--format')
      ? [...baseArgs]
      : [...baseArgs, '--json'];

    addMessage('command', label);
    setIsRunning(true);

    const result = await runCommand([command, ...args], { silent: false });

    setIsRunning(false);

    if (result.ok) {
      // Try to parse JSON output and render nicely
      try {
        const data = JSON.parse(result.stdout);
        addMessage('result', formatOutput(command, data));
      } catch {
        // Plain text output
        addMessage('result', result.stdout.trim());
      }
    } else {
      addMessage('error', result.stderr || result.error || 'Command failed');
    }
  }

  function formatOutput(command, data) {
    // Format structured output from Rust binary
    switch (command) {
      case 'review': {
        const findings = data.findings || data;
        if (!Array.isArray(findings) || findings.length === 0) {
          return '✅  No vulnerabilities found.';
        }
        const lines = [
          '📋  Review Results: ' + findings.length + ' finding(s)',
          '',
        ];
        const bySev = {};
        for (const f of findings) {
          const sev = f.severity || 'INFO';
          if (!bySev[sev]) bySev[sev] = [];
          bySev[sev].push(f);
        }
        for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
          if (bySev[sev]) {
            lines.push(`  ${sev}: ${bySev[sev].length}`);
            for (const f of bySev[sev].slice(0, 5)) {
              const fp = f.file_path ? f.file_path.split('/').pop() : '';
              const ln = f.line_number ? ':' + f.line_number : '';
              lines.push(`    • ${f.title}  ${fp}${ln}`);
            }
            if (bySev[sev].length > 5) {
              lines.push(`    ... and ${bySev[sev].length - 5} more`);
            }
            lines.push('');
          }
        }
        return lines.join('\n');
      }
      case 'attack': {
        const chains = data.chains || data;
        if (!Array.isArray(chains) || chains.length === 0) {
          return '✅  No attack chains found. Weaknesses are isolated.';
        }
        const lines = [
          '🕸  Attack Chains: ' + chains.length + ' discovered',
          '',
        ];
        for (const chain of chains.slice(0, 5)) {
          const name = chain.chain_type || chain.name || 'Unknown';
          const risk = chain.risk_score ? chain.risk_score.toFixed(1) : '?';
          lines.push(`  ${chain.entry_point || ''}`);
          lines.push(`  ↓  Risk: ${risk}/10  |  ${name}`);
          lines.push(`  ${chain.impact || ''}`);
          lines.push('');
        }
        if (chains.length > 5) {
          lines.push(`  ... and ${chains.length - 5} more chains`);
        }
        return lines.join('\n');
      }
      case 'deps': {
        const findings = data.findings || data;
        if (!Array.isArray(findings) || findings.length === 0) {
          return '✅  No vulnerable dependencies found.';
        }
        const lines = ['📦  Vulnerable Dependencies: ' + findings.length, ''];
        for (const f of findings.slice(0, 10)) {
          lines.push(`  • ${f.title}  [${f.severity}]`);
        }
        if (findings.length > 10) {
          lines.push(`  ... and ${findings.length - 10} more`);
        }
        return lines.join('\n');
      }
      case 'secrets': {
        const findings = data.findings || data;
        if (!Array.isArray(findings) || findings.length === 0) {
          return '✅  No secrets found.';
        }
        const lines = ['🔑  Secrets Found: ' + findings.length, ''];
        for (const f of findings.slice(0, 10)) {
          const fp = f.file_path ? f.file_path.split('/').pop() : '';
          const ln = f.line_number ? ':' + f.line_number : '';
          lines.push(`  • ${f.title}  ${fp}${ln}  [${f.severity}]`);
        }
        if (findings.length > 10) {
          lines.push(`  ... and ${findings.length - 10} more`);
        }
        return lines.join('\n');
      }
      case 'status': {
        return [
          '📊  Project Status',
          `  Index:    ${data.indexed ? '✅ Indexed' : '📭 Not indexed'}`,
          `  Files:    ${data.file_count || 0}`,
          `  Chunks:   ${data.chunk_count || 0}`,
          `  API Key:  ${data.api_key ? '✅ Set' : '❌ Missing'}`,
          `  Project:  ${data.project_path || ''}`,
        ].join('\n');
      }
      case 'fix': {
        const fixes = data.fixes || data.findings || data;
        if (!Array.isArray(fixes) || fixes.length === 0) {
          return 'No fixable findings. Run /review first.';
        }
        const lines = ['🛠  Fixable Findings', ''];
        // Show as list since /fix in TUI is complex
        for (const f of fixes.slice(0, 10)) {
          lines.push(`  • ${f.title}  [${f.severity}]  (${(f.risk_score || 0).toFixed(1)}/10)`);
        }
        lines.push('');
        lines.push('Run /fix --id <ID> to fix a specific finding.');
        return lines.join('\n');
      }
      case 'report': {
        const score = data.security_score !== undefined ? data.security_score : '?';
        const total = data.total_findings || 0;
        return [
          '📊  Security Report',
          `  Score:  ${score}/100`,
          `  Total:  ${total} finding(s)`,
          `  Critical: ${data.summary?.critical || 0}`,
          `  High:     ${data.summary?.high || 0}`,
          `  Medium:   ${data.summary?.medium || 0}`,
          `  Low:      ${data.summary?.low || 0}`,
        ].join('\n');
      }
      default:
        return data;
    }
  }

  function handleCloseHelp() {
    setShowHelp(false);
  }

  return React.createElement(Box, {
    flexDirection: 'column',
    height: '100%',
    width: '100%',
  },
    React.createElement(ChatArea, {
      messages,
      isRunning,
    }),
    showHelp && React.createElement(CommandHelp, { onClose: handleCloseHelp }),
    React.createElement(InputBox, {
      value: input,
      onChange: setInput,
      onSubmit: handleSubmit,
      isRunning,
    }),
    React.createElement(StatusBar, {
      status,
      isRunning,
      messageCount: messages.length,
    })
  );
}

// Render the app
const { waitUntilExit } = render(React.createElement(App));

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
  process.exit(0);
});

waitUntilExit().catch(() => {});
