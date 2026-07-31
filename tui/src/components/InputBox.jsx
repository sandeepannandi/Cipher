const React = require('react');
const { Box, Text, useInput } = require('ink');

const MODELS = ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768', 'gemma2-9b-it'];

const COMMANDS = [
  { cmd: 'init',         desc: 'Index your codebase for analysis' },
  { cmd: 'init --force', desc: 'Force re-index' },
  { cmd: 'review',                          desc: 'Scan for OWASP Top 10 vulnerabilities' },
  { cmd: 'review --ai',                     desc: 'Review with AI-powered deep analysis' },
  { cmd: 'review --verify',                  desc: 'Review + AI-verify findings (filter false positives)' },
  { cmd: 'review --max-findings 10',        desc: 'Review (limit to top 10 findings)' },
  { cmd: 'review --min-severity high',      desc: 'Review (only high+ severity)' },
  { cmd: 'review --min-confidence medium',  desc: 'Review (only medium+ confidence)' },
  { cmd: 'review --format sarif',           desc: 'Review → SARIF JSON output' },
  { cmd: 'review --format json',            desc: 'Review → machine-readable JSON' },
  { cmd: 'review --output file.json',       desc: 'Write review output to file' },
  { cmd: 'deps',         desc: 'Check dependency vulnerabilities' },
  { cmd: 'deps --online',desc: 'Check deps with OSV.dev API' },
  { cmd: 'deps --fail-on high', desc: 'Deps check, fail on high+' },
  { cmd: 'secrets',      desc: 'Scan for leaked credentials' },
  { cmd: 'secrets --fail-on high', desc: 'Secrets scan, fail on high+' },
  { cmd: 'ask',          desc: 'Ask a security question (uses AI)' },
  { cmd: 'report',       desc: 'Generate security report' },
  { cmd: 'fix --list',   desc: 'List fixable findings' },
  { cmd: 'fix --dry-run',desc: 'Preview fixes without applying' },
  { cmd: 'fix --verify', desc: 'Fix + compile-check each patch (revert broken fixes)' },
  { cmd: 'attack',       desc: 'Discover attack chains' },
  { cmd: 'ci',           desc: 'Run all scans (CI mode)' },
  { cmd: 'config',       desc: 'Show or set configuration' },
  { cmd: 'zeroday',                               desc: '3-layer zero-day anomaly detection' },
  { cmd: 'zeroday --ai',                           desc: 'Zero-day + AI-powered analysis' },
  { cmd: 'zeroday --anomaly-only',                 desc: 'Zero-day: anomaly layer only' },
  { cmd: 'zeroday --no-flow',                      desc: 'Zero-day: skip taint flow analysis' },
  { cmd: 'zeroday --format json',                  desc: 'Zero-day → JSON output' },  { cmd: 'zeroday --format sarif',                  desc: 'Zero-day → SARIF JSON output' },
  { cmd: 'sbom',                                       desc: 'Generate CycloneDX SBOM' },
  { cmd: 'sbom --format spdx',                         desc: 'Generate SPDX SBOM' },
  { cmd: 'sbom --output bom.json',                     desc: 'Write SBOM to file' },
  { cmd: 'model',        desc: 'Show or switch AI model' },
  { cmd: 'status',       desc: 'Show index and API key status' },
  { cmd: 'clear',        desc: 'Clear messages' },
  { cmd: 'exit',         desc: 'Exit the TUI' },
];

const MAX_VISIBLE = 10;

function InputBox({ value, onChange, onSubmit, isRunning, showAskPrompt, onNavigateHistory }) {
  const [selectedIdx, setSelectedIdx] = React.useState(0);
  const [dropdownScroll, setDropdownScroll] = React.useState(0);

  const showDropdown = value.trim().startsWith('/') && value.trim().length > 0;
  const filterText = value.trim().slice(1).toLowerCase();
  const filtered = showDropdown ? COMMANDS.filter((c) => c.cmd.toLowerCase().startsWith(filterText)) : [];
  const maxDropdownScroll = Math.max(0, filtered.length - MAX_VISIBLE);

  useInput((input, key) => {
    if (isRunning) return;

    // History navigation (up/down when dropdown is closed or empty)
    if (key.upArrow && (!showDropdown || filtered.length === 0)) {
      if (onNavigateHistory) onNavigateHistory('up');
      return;
    }
    if (key.downArrow && (!showDropdown || filtered.length === 0)) {
      if (onNavigateHistory) onNavigateHistory('down');
      return;
    }

    if (key.return) {
      if (showDropdown && filtered.length > 0 && filtered[selectedIdx]) {
        const selected = filtered[selectedIdx];
        if (selected.cmd === 'model') {
          onChange('');
          onSubmit('/model');
          return;
        }
        onChange('');
        onSubmit('/' + selected.cmd);
        return;
      }
      onSubmit(value);
      return;
    }
    if (showDropdown && filtered.length > 0) {
      if (key.upArrow) {
        const newIdx = Math.max(0, selectedIdx - 1);
        setSelectedIdx(newIdx);
        if (newIdx < dropdownScroll) setDropdownScroll(newIdx);
        return;
      }
      if (key.downArrow) {
        const newIdx = Math.min(filtered.length - 1, selectedIdx + 1);
        setSelectedIdx(newIdx);
        if (newIdx >= dropdownScroll + MAX_VISIBLE) setDropdownScroll(newIdx - MAX_VISIBLE + 1);
        return;
      }
    }
    if (key.escape) { onChange(''); return; }
    if (key.backspace || key.delete) { onChange(value.slice(0, -1)); setSelectedIdx(0); setDropdownScroll(0); return; }
    if (input.length >= 1 && !key.ctrl) { onChange(value + input); setSelectedIdx(0); setDropdownScroll(0); }
  });

  React.useEffect(() => { setSelectedIdx(0); setDropdownScroll(0); }, [value]);

  const visible = filtered.slice(dropdownScroll, dropdownScroll + MAX_VISIBLE);

  const isEmpty = value.trim().length === 0;
  const startsWithSlash = value.trim().startsWith('/');
  const cmdWord = startsWithSlash ? value.trim().slice(1).split(/\s+/)[0] : '';
  const isExactMatch = startsWithSlash && COMMANDS.some((c) => c.cmd === cmdWord);
  const isPartialMatch = startsWithSlash && !isExactMatch && COMMANDS.some((c) => c.cmd.startsWith(cmdWord));

  const isModelCommand = startsWithSlash && cmdWord === 'model';
  const modelFilter = isModelCommand ? value.trim().slice(7).toLowerCase() : '';
  const modelSuggestions = isModelCommand && value.trim().length > 7
    ? MODELS.filter((m) => m.toLowerCase().startsWith(modelFilter))
    : [];

  return React.createElement(Box, { flexDirection: 'column', marginTop: 1 },

    showDropdown && filtered.length > 0 && React.createElement(Box, {
      flexDirection: 'column', borderStyle: 'single', borderColor: 'yellow',
      marginLeft: 1, marginRight: 1, marginBottom: 0,
      height: MAX_VISIBLE + 4,
    },
      dropdownScroll > 0 && React.createElement(Box, {},
        React.createElement(Text, { color: 'green', dim: true }, '  ↑ ' + dropdownScroll + ' more')),
      ...visible.map((cmd, i) => {
        const globalIdx = dropdownScroll + i;
        return React.createElement(Box, { key: cmd.cmd, flexDirection: 'row' },
          React.createElement(Text, {
            color: globalIdx === selectedIdx ? 'yellow' : 'white',
            bold: globalIdx === selectedIdx,
          }, '  ' + cmd.cmd.padEnd(22) + cmd.desc));
      }),
      dropdownScroll < maxDropdownScroll && React.createElement(Box, {},
        React.createElement(Text, { color: 'green', dim: true }, '  ↓ ' + (filtered.length - dropdownScroll - MAX_VISIBLE) + ' more'))),

    isModelCommand && modelSuggestions.length > 0 && React.createElement(Box, {
      flexDirection: 'column', borderStyle: 'single', borderColor: 'yellow',
      marginLeft: 1, marginRight: 1, marginBottom: 0,
      height: modelSuggestions.length + 1,
    },
      ...modelSuggestions.map((m, i) =>
        React.createElement(Box, { key: m, flexDirection: 'row' },
          React.createElement(Text, { color: 'yellow' }, '  ' + m)))),

    React.createElement(Box, { flexDirection: 'row', paddingLeft: 1, paddingRight: 1, marginTop: showDropdown && filtered.length > 0 ? 0 : 0 },
      React.createElement(Text, { color: 'green' }, showAskPrompt ? '? ' : '> '),
      isEmpty && !showAskPrompt && React.createElement(Text, { color: 'white', dim: true }, ' Type /help or ask a question...'),
      isEmpty && showAskPrompt && React.createElement(Text, { color: 'yellow' }, ' Type your question...'),
      !isEmpty && (startsWithSlash
        ? React.createElement(Box, { flexDirection: 'row' },
            React.createElement(Text, { color: 'yellow' }, '/'),
            React.createElement(Text, { color: (isExactMatch || isPartialMatch) ? 'yellow' : 'white' }, value.trim().slice(1)))
        : React.createElement(Text, { color: 'white' }, value.trim()))),
  );
}

module.exports.InputBox = InputBox;
