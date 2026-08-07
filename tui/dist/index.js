var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// src/components/Message.jsx
var require_Message = __commonJS({
  "src/components/Message.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2 } = require("ink");
    var TYPE_STYLES = {
      user: { color: "white", label: "You" },
      command: { color: "white", label: "Command" },
      result: { color: "white", label: "" },
      error: { color: "red", label: "Error" },
      system: { color: "green", label: "" }
    };
    function Message({ message }) {
      const style = TYPE_STYLES[message.type] || TYPE_STYLES.system;
      const lines = (message.text || "").split("\n");
      const isResult = message.type === "result";
      const isUser = message.type === "user";
      if (isUser) {
        return React2.createElement(
          Box2,
          { flexDirection: "column", marginTop: 1 },
          React2.createElement(
            Box2,
            {
              flexDirection: "column",
              borderStyle: "round",
              borderColor: style.color,
              paddingLeft: 1,
              paddingRight: 1,
              paddingTop: 0,
              paddingBottom: 0
            },
            React2.createElement(Text2, { color: style.color, bold: true }, style.label),
            ...lines.filter((l) => l.trim()).map((line, i) => React2.createElement(Text2, { key: i, color: style.color, wrap: "wrap" }, line))
          )
        );
      }
      if (isResult) {
        return React2.createElement(
          Box2,
          { flexDirection: "column", marginTop: 0, marginBottom: 1 },
          ...lines.map((line, i) => {
            if (!line.trim()) return React2.createElement(Box2, { key: i, height: 1 });
            return React2.createElement(
              Box2,
              { key: i, paddingLeft: 2 },
              React2.createElement(Text2, { color: style.color, wrap: "wrap" }, line)
            );
          })
        );
      }
      return React2.createElement(
        Box2,
        { flexDirection: "column", marginTop: 1 },
        style.label ? React2.createElement(
          Box2,
          { paddingLeft: 2, marginBottom: 0 },
          React2.createElement(Text2, { color: style.color, bold: true }, style.label)
        ) : null,
        ...lines.map((line, i) => {
          if (!line.trim()) return React2.createElement(Box2, { key: i, height: 1 });
          return React2.createElement(
            Box2,
            { key: i, paddingLeft: 2 },
            React2.createElement(Text2, { color: style.color, wrap: "wrap" }, line)
          );
        })
      );
    }
    module2.exports.Message = Message;
  }
});

// src/components/ChatArea.jsx
var require_ChatArea = __commonJS({
  "src/components/ChatArea.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2, useInput: useInput2 } = require("ink");
    var { Message } = require_Message();
    function ChatArea2({ messages, isRunning, model }) {
      const [scrollOffset, setScrollOffset] = React2.useState(0);
      React2.useEffect(() => {
        setScrollOffset(0);
      }, [messages.length]);
      useInput2((_input, key) => {
        if (key.upArrow) setScrollOffset((p) => Math.min(p + 1, Math.max(0, messages.length - 10)));
        if (key.downArrow) setScrollOffset((p) => Math.max(0, p - 1));
        if (key.pageUp) setScrollOffset((p) => Math.min(p + 10, Math.max(0, messages.length - 10)));
        if (key.pageDown) setScrollOffset((p) => Math.max(0, p - 10));
      });
      const visible = messages.filter((m) => m.id !== "welcome" || m.text);
      const start = Math.max(0, visible.length - 10 - scrollOffset);
      const end = Math.min(visible.length, start + 10);
      const display = visible.slice(start, end);
      const hasMore = visible.length > 10 && scrollOffset > 0;
      return React2.createElement(
        Box2,
        { flexDirection: "column", flexGrow: 1, paddingLeft: 1, paddingRight: 1, paddingTop: 1 },
        React2.createElement(
          Box2,
          { flexDirection: "column", marginBottom: 1 },
          React2.createElement(
            Box2,
            {},
            React2.createElement(Text2, { bold: true, color: "yellow" }, [
              "  ____ ___ ____  _   _ _____ ____  ",
              " / ___|_ _|  _ \\| | | | ____|  _ \\ ",
              "| |    | || |_) | |_| |  _| | |_) |",
              "| |___ | ||  __/|  _  | |___|  _ < ",
              " \\____|___|_|   |_| |_|_____|_| \\_\\"
            ].join("\n"))
          ),
          React2.createElement(
            Box2,
            { marginTop: 1 },
            React2.createElement(Text2, { bold: true, color: "yellow" }, "AI Security Engineer")
          ),
          React2.createElement(Text2, { color: "green", dim: true }, "/help for commands  Ctrl+K for palette  model: " + model)
        ),
        hasMore && React2.createElement(
          Box2,
          { marginBottom: 1 },
          React2.createElement(Text2, { color: "green", dim: true }, "up arrow for older messages")
        ),
        ...display.map((msg) => React2.createElement(Message, { key: msg.id, message: msg })),
        isRunning && React2.createElement(
          Box2,
          { marginTop: 1, marginLeft: 2 },
          React2.createElement(Text2, { color: "yellow" }, "running...")
        ),
        React2.createElement(Box2, { height: 1 })
      );
    }
    module2.exports.ChatArea = ChatArea2;
  }
});

// src/components/InputBox.jsx
var require_InputBox = __commonJS({
  "src/components/InputBox.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2, useInput: useInput2 } = require("ink");
    var MODELS2 = [
      "llama-3.3-70b-versatile",
      "mixtral-8x7b-32768",
      "gemma2-9b-it",
      "gpt-4o-mini",
      "claude-3-7-sonnet-20250219"
    ];
    var COMMANDS = [
      { cmd: "init", desc: "Index your codebase for analysis" },
      { cmd: "init --force", desc: "Force re-index" },
      { cmd: "review", desc: "Scan for OWASP Top 10 vulnerabilities" },
      { cmd: "review --ai", desc: "Review with AI-powered deep analysis" },
      { cmd: "review --verify", desc: "Review + AI-verify findings (filter false positives)" },
      { cmd: "review --max-findings 10", desc: "Review (limit to top 10 findings)" },
      { cmd: "review --min-severity high", desc: "Review (only high+ severity)" },
      { cmd: "review --min-confidence medium", desc: "Review (only medium+ confidence)" },
      { cmd: "review --format sarif", desc: "Review \u2192 SARIF JSON output" },
      { cmd: "review --format json", desc: "Review \u2192 machine-readable JSON" },
      { cmd: "review --output file.json", desc: "Write review output to file" },
      { cmd: "deps", desc: "Check dependency vulnerabilities" },
      { cmd: "deps --online", desc: "Check deps with OSV.dev API" },
      { cmd: "deps --fail-on high", desc: "Deps check, fail on high+" },
      { cmd: "secrets", desc: "Scan for leaked credentials" },
      { cmd: "secrets --fail-on high", desc: "Secrets scan, fail on high+" },
      { cmd: "ask", desc: "Ask a security question (uses AI)" },
      { cmd: "report", desc: "Generate security report" },
      { cmd: "report --format html", desc: "Report \u2192 browser-ready HTML dashboard" },
      { cmd: "fix --list", desc: "List fixable findings" },
      { cmd: "fix --dry-run", desc: "Preview fixes without applying" },
      { cmd: "fix --verify", desc: "Fix + compile-check each patch (revert broken fixes)" },
      { cmd: "fix --pr", desc: "Fix + open a GitHub PR with the fixes" },
      { cmd: "attack", desc: "Discover attack chains" },
      { cmd: "attack --flow", desc: "Attack chains + real data-flow evidence" },
      { cmd: "trace", desc: "Trace untrusted data across files (taint flow)" },
      { cmd: "pr", desc: "Post a GitHub PR security review comment" },
      { cmd: "pr --diff", desc: "Diff-aware PR review (changed lines only)" },
      { cmd: "watch", desc: "Monitor for new findings (every 6h)" },
      { cmd: "watch --once", desc: "Watch: single scan, report what is new" },
      { cmd: "watch --pr", desc: "Watch + auto-fix new findings via GitHub PR" },
      { cmd: "ci", desc: "Run all scans (CI mode)" },
      { cmd: "config", desc: "Show or set configuration" },
      { cmd: "config set provider groq", desc: "Switch AI provider \u2192 Groq" },
      { cmd: "config set provider openai", desc: "Switch AI provider \u2192 OpenAI" },
      { cmd: "config set provider anthropic", desc: "Switch AI provider \u2192 Anthropic" },
      { cmd: "pentest", desc: "Autonomous AI security engineer (agent hunts + reports)" },
      { cmd: "pentest --json", desc: "Pentest \u2192 JSON findings" },
      { cmd: "pentest --url http://localhost:8080", desc: "Live pentest: HTTP tools + exploit validators" },
      { cmd: 'pentest "hunt and exploit vulnerabilities" --url http://localhost:8080 --sub-agents 6', desc: "Live pentest: parallel specialist agents" },
      { cmd: 'pentest "test the login" --url http://localhost:8080 --config app.yaml', desc: "Live pentest with YAML config: auth, ROE, scope rules" },
      { cmd: "zeroday", desc: "3-layer zero-day anomaly detection" },
      { cmd: "zeroday --ai", desc: "Zero-day + AI-powered analysis" },
      { cmd: "zeroday --anomaly-only", desc: "Zero-day: anomaly layer only" },
      { cmd: "zeroday --no-flow", desc: "Zero-day: skip taint flow analysis" },
      { cmd: "zeroday --format json", desc: "Zero-day \u2192 JSON output" },
      { cmd: "zeroday --format sarif", desc: "Zero-day \u2192 SARIF JSON output" },
      { cmd: "sbom", desc: "Generate CycloneDX SBOM" },
      { cmd: "sbom --format spdx", desc: "Generate SPDX SBOM" },
      { cmd: "sbom --output bom.json", desc: "Write SBOM to file" },
      { cmd: "model", desc: "Show or switch AI model" },
      { cmd: "status", desc: "Show index and API key status" },
      { cmd: "clear", desc: "Clear messages" },
      { cmd: "exit", desc: "Exit the TUI" }
    ];
    var MAX_VISIBLE = 10;
    function InputBox2({ value, onChange, onSubmit, isRunning, showAskPrompt, onNavigateHistory }) {
      const [selectedIdx, setSelectedIdx] = React2.useState(0);
      const [dropdownScroll, setDropdownScroll] = React2.useState(0);
      const showDropdown = value.trim().startsWith("/") && value.trim().length > 0;
      const filterText = value.trim().slice(1).toLowerCase();
      const filtered = showDropdown ? COMMANDS.filter((c) => c.cmd.toLowerCase().startsWith(filterText)) : [];
      const maxDropdownScroll = Math.max(0, filtered.length - MAX_VISIBLE);
      useInput2((input, key) => {
        if (isRunning) return;
        if (key.upArrow && (!showDropdown || filtered.length === 0)) {
          if (onNavigateHistory) onNavigateHistory("up");
          return;
        }
        if (key.downArrow && (!showDropdown || filtered.length === 0)) {
          if (onNavigateHistory) onNavigateHistory("down");
          return;
        }
        if (key.return) {
          if (showDropdown && filtered.length > 0 && filtered[selectedIdx]) {
            const selected = filtered[selectedIdx];
            if (selected.cmd === "model") {
              onChange("");
              onSubmit("/model");
              return;
            }
            onChange("");
            onSubmit("/" + selected.cmd);
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
        if (key.escape) {
          onChange("");
          return;
        }
        if (key.backspace || key.delete) {
          onChange(value.slice(0, -1));
          setSelectedIdx(0);
          setDropdownScroll(0);
          return;
        }
        if (input.length >= 1 && !key.ctrl) {
          onChange(value + input);
          setSelectedIdx(0);
          setDropdownScroll(0);
        }
      });
      React2.useEffect(() => {
        setSelectedIdx(0);
        setDropdownScroll(0);
      }, [value]);
      const visible = filtered.slice(dropdownScroll, dropdownScroll + MAX_VISIBLE);
      const isEmpty = value.trim().length === 0;
      const startsWithSlash = value.trim().startsWith("/");
      const cmdWord = startsWithSlash ? value.trim().slice(1).split(/\s+/)[0] : "";
      const isExactMatch = startsWithSlash && COMMANDS.some((c) => c.cmd === cmdWord);
      const isPartialMatch = startsWithSlash && !isExactMatch && COMMANDS.some((c) => c.cmd.startsWith(cmdWord));
      const isModelCommand = startsWithSlash && cmdWord === "model";
      const modelFilter = isModelCommand ? value.trim().slice(7).toLowerCase() : "";
      const modelSuggestions = isModelCommand && value.trim().length > 7 ? MODELS2.filter((m) => m.toLowerCase().startsWith(modelFilter)) : [];
      return React2.createElement(
        Box2,
        { flexDirection: "column", marginTop: 1 },
        showDropdown && filtered.length > 0 && React2.createElement(
          Box2,
          {
            flexDirection: "column",
            borderStyle: "single",
            borderColor: "yellow",
            marginLeft: 1,
            marginRight: 1,
            marginBottom: 0,
            height: MAX_VISIBLE + 4
          },
          dropdownScroll > 0 && React2.createElement(
            Box2,
            {},
            React2.createElement(Text2, { color: "green", dim: true }, "  \u2191 " + dropdownScroll + " more")
          ),
          ...visible.map((cmd, i) => {
            const globalIdx = dropdownScroll + i;
            return React2.createElement(
              Box2,
              { key: cmd.cmd, flexDirection: "row" },
              React2.createElement(Text2, {
                color: globalIdx === selectedIdx ? "yellow" : "white",
                bold: globalIdx === selectedIdx
              }, "  " + cmd.cmd.padEnd(22) + cmd.desc)
            );
          }),
          dropdownScroll < maxDropdownScroll && React2.createElement(
            Box2,
            {},
            React2.createElement(Text2, { color: "green", dim: true }, "  \u2193 " + (filtered.length - dropdownScroll - MAX_VISIBLE) + " more")
          )
        ),
        isModelCommand && modelSuggestions.length > 0 && React2.createElement(
          Box2,
          {
            flexDirection: "column",
            borderStyle: "single",
            borderColor: "yellow",
            marginLeft: 1,
            marginRight: 1,
            marginBottom: 0,
            height: modelSuggestions.length + 1
          },
          ...modelSuggestions.map((m, i) => React2.createElement(
            Box2,
            { key: m, flexDirection: "row" },
            React2.createElement(Text2, { color: "yellow" }, "  " + m)
          ))
        ),
        React2.createElement(
          Box2,
          { flexDirection: "row", paddingLeft: 1, paddingRight: 1, marginTop: showDropdown && filtered.length > 0 ? 0 : 0 },
          React2.createElement(Text2, { color: "green" }, showAskPrompt ? "? " : "> "),
          isEmpty && !showAskPrompt && React2.createElement(Text2, { color: "white", dim: true }, " Type /help or ask a question..."),
          isEmpty && showAskPrompt && React2.createElement(Text2, { color: "yellow" }, " Type your question..."),
          !isEmpty && (startsWithSlash ? React2.createElement(
            Box2,
            { flexDirection: "row" },
            React2.createElement(Text2, { color: "yellow" }, "/"),
            React2.createElement(Text2, { color: isExactMatch || isPartialMatch ? "yellow" : "white" }, value.trim().slice(1))
          ) : React2.createElement(Text2, { color: "white" }, value.trim()))
        )
      );
    }
    module2.exports.InputBox = InputBox2;
  }
});

// src/components/StatusBar.jsx
var require_StatusBar = __commonJS({
  "src/components/StatusBar.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2 } = require("ink");
    var indexColors = { indexed: "green", "not indexed": "yellow", unknown: "green" };
    var keyColors = { set: "green", missing: "yellow", unknown: "green" };
    var providerColors = { groq: "yellow", openai: "green", anthropic: "magenta" };
    function StatusBar2({ status, model, isRunning, messageCount }) {
      return React2.createElement(
        Box2,
        {
          flexDirection: "row",
          borderStyle: "single",
          borderColor: "green",
          paddingLeft: 1,
          paddingRight: 1
        },
        React2.createElement(Text2, { color: "green" }, " index "),
        React2.createElement(Text2, { color: indexColors[status.index] || "green" }, status.index),
        React2.createElement(Text2, { color: "green" }, " | provider "),
        React2.createElement(Text2, { color: providerColors[status.provider] || "white" }, status.provider || "groq"),
        React2.createElement(Text2, { color: "green" }, " | api "),
        React2.createElement(Text2, { color: keyColors[status.apiKey] || "green" }, status.apiKey),
        React2.createElement(Box2, { flexGrow: 1 }),
        React2.createElement(
          Text2,
          { color: isRunning ? "yellow" : "green" },
          isRunning ? "running" : ""
        ),
        isRunning && React2.createElement(Text2, { color: "green" }, " | "),
        React2.createElement(Text2, { color: "green" }, " model "),
        React2.createElement(Text2, { color: "white" }, model),
        React2.createElement(Text2, { color: "green" }, " | "),
        React2.createElement(Text2, { color: "green" }, messageCount + " msgs")
      );
    }
    module2.exports.StatusBar = StatusBar2;
  }
});

// src/components/CommandHelp.jsx
var require_CommandHelp = __commonJS({
  "src/components/CommandHelp.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2, useInput: useInput2 } = require("ink");
    var COMMANDS = [
      { cmd: "/init", desc: "Index your codebase for analysis" },
      { cmd: "/init --force", desc: "Force re-index" },
      { cmd: "/review", desc: "Scan for OWASP Top 10 vulnerabilities" },
      { cmd: "/review --ai", desc: "Review with AI-powered deep analysis" },
      { cmd: "/review --verify", desc: "Review + AI-verify findings (filter false positives)" },
      { cmd: "/review --max-findings 10", desc: "Limit review to top 10 findings" },
      { cmd: "/review --min-severity high", desc: "Show only high+ severity findings" },
      { cmd: "/review --min-confidence medium", desc: "Show only medium+ confidence findings" },
      { cmd: "/review --format sarif", desc: "Review \u2192 SARIF JSON output" },
      { cmd: "/review --format json", desc: "Review \u2192 machine-readable JSON" },
      { cmd: "/review --output file.json", desc: "Write review output to a file" },
      { cmd: "/deps", desc: "Check dependency vulnerabilities" },
      { cmd: "/deps --online", desc: "Check deps with OSV.dev API" },
      { cmd: "/deps --fail-on high", desc: "Deps check, exit 1 on high+" },
      { cmd: "/secrets", desc: "Scan for leaked credentials" },
      { cmd: "/secrets --fail-on high", desc: "Secrets scan, exit 1 on high+" },
      { cmd: "/ask", desc: "Ask a security question (uses AI)" },
      { cmd: "/report", desc: "Generate security report" },
      { cmd: "/report --format html", desc: "Report \u2192 exports cipher-ai-report.html dashboard" },
      { cmd: "/report --type executive", desc: "Executive summary report" },
      { cmd: "/fix --list", desc: "List fixable findings" },
      { cmd: "/fix --dry-run", desc: "Preview fixes without applying" },
      { cmd: "/fix --verify", desc: "Fix + compile-check each patch (revert broken fixes)" },
      { cmd: "/fix --pr", desc: "Fix + open a GitHub PR with the fixes" },
      { cmd: "/attack", desc: "Discover attack chains" },
      { cmd: "/attack --flow", desc: "Attack chains + real data-flow evidence" },
      { cmd: "/attack --chain privilege-escalation", desc: "Attack chains filtered by type" },
      { cmd: "/attack --depth 5", desc: "Deeper attack chain analysis" },
      { cmd: '/trace "can users become admin?"', desc: "Trace untrusted data across files (taint flow)" },
      { cmd: '/trace --ai "is this SQL injectable?"', desc: "Trace + AI-enriched path analysis" },
      { cmd: '/trace --json "user input reaches exec"', desc: "Trace \u2192 JSON output" },
      { cmd: "/pr --dry-run", desc: "Preview a PR security review comment" },
      { cmd: "/pr --diff", desc: "Diff-aware PR review: only findings on changed lines (+ inline comments)" },
      { cmd: "/watch", desc: "Monitor for new findings (every 6h, uses saved state)" },
      { cmd: "/watch --once", desc: "Watch: single scan, report what is new since last scan" },
      { cmd: "/watch --pr", desc: "Watch + auto-fix new findings and open a GitHub PR" },
      { cmd: "/watch --interval 60", desc: "Watch: scan every 60 minutes" },
      { cmd: "/ci", desc: "Run all 5 scans (review+secrets+deps+zeroday+attack)" },
      { cmd: "/ci --format json", desc: "CI \u2192 machine-readable JSON output" },
      { cmd: "/ci --format json --output ci.json", desc: "CI \u2192 JSON written to file" },
      { cmd: "/ci --fail-on critical", desc: "CI: fail only on critical findings" },
      { cmd: "/config", desc: "Show or set configuration" },
      { cmd: "/config set provider openai", desc: "Switch AI provider (groq | openai | anthropic)" },
      { cmd: "/config set groq-api-key <key>", desc: "Persist Groq API key" },
      { cmd: "/config set openai-api-key <key>", desc: "Persist OpenAI API key" },
      { cmd: "/config set anthropic-api-key <key>", desc: "Persist Anthropic API key" },
      { cmd: "/pentest", desc: "Autonomous AI security engineer (agent hunts + reports findings)" },
      { cmd: '/pentest "can users escalate privileges?"', desc: "Pentest with a specific objective" },
      { cmd: "/pentest --json", desc: "Pentest \u2192 machine-readable JSON" },
      { cmd: "/pentest --max-turns 60", desc: "Pentest with a larger agent budget" },
      { cmd: "/pentest --url http://localhost:8080", desc: "Live mode: HTTP tools + exploit validators (no exploit, no report)" },
      { cmd: '/pentest "hunt and exploit vulnerabilities" --url http://localhost:8080', desc: "Live pentest: agent proves exploits against a running target" },
      { cmd: '/pentest "hunt and exploit vulnerabilities" --url http://localhost:8080 --sub-agents 6', desc: "Live pentest: parallel specialist sub-agents (default 4)" },
      { cmd: '/pentest "test the login" --url http://localhost:8080 --config app.yaml', desc: "Live pentest with YAML config: auth flow, rules of engagement, focus/avoid scope" },
      { cmd: "/zeroday", desc: "3-layer zero-day anomaly detection" },
      { cmd: "/zeroday --ai", desc: "Zero-day + AI-powered analysis" },
      { cmd: "/zeroday --anomaly-only", desc: "Zero-day: anomaly layer only" },
      { cmd: "/zeroday --no-flow", desc: "Zero-day: skip taint flow analysis" },
      { cmd: "/zeroday --format json", desc: "Zero-day \u2192 JSON output" },
      { cmd: "/zeroday --format sarif", desc: "Zero-day \u2192 SARIF JSON output" },
      { cmd: "/sbom", desc: "Generate CycloneDX SBOM" },
      { cmd: "/sbom --format spdx", desc: "Generate SPDX SBOM" },
      { cmd: "/sbom --output bom.json", desc: "Write SBOM to file" },
      { cmd: "/model", desc: "Show or switch AI model (any provider)" },
      { cmd: "/status", desc: "Show index and API key status" },
      { cmd: "/clear", desc: "Clear messages" },
      { cmd: "/exit", desc: "Exit the TUI" }
    ];
    var MAX_VISIBLE = 12;
    function CommandHelp2({ onClose }) {
      const [scrollOffset, setScrollOffset] = React2.useState(0);
      const maxOffset = Math.max(0, COMMANDS.length - MAX_VISIBLE);
      useInput2((_input, key) => {
        if (key.escape) onClose();
        if (key.upArrow) setScrollOffset((p) => Math.max(0, p - 1));
        if (key.downArrow) setScrollOffset((p) => Math.min(maxOffset, p + 1));
        if (key.pageUp) setScrollOffset((p) => Math.max(0, p - MAX_VISIBLE));
        if (key.pageDown) setScrollOffset((p) => Math.min(maxOffset, p + MAX_VISIBLE));
      });
      const visible = COMMANDS.slice(scrollOffset, scrollOffset + MAX_VISIBLE);
      return React2.createElement(
        Box2,
        {
          flexDirection: "column",
          borderStyle: "round",
          borderColor: "yellow",
          padding: 1,
          marginLeft: 2,
          marginRight: 2,
          marginTop: 1,
          height: MAX_VISIBLE + 5
        },
        React2.createElement(
          Box2,
          { marginBottom: 0 },
          React2.createElement(Text2, { bold: true, color: "yellow" }, " Commands (Esc to close) ")
        ),
        scrollOffset > 0 && React2.createElement(
          Box2,
          {},
          React2.createElement(Text2, { color: "green", dim: true }, "  \u2191 " + scrollOffset + " more")
        ),
        ...visible.map((cmd) => React2.createElement(
          Box2,
          { key: cmd.cmd, flexDirection: "row" },
          React2.createElement(
            Box2,
            { width: 24 },
            React2.createElement(Text2, { color: "yellow", bold: true }, "  " + cmd.cmd)
          ),
          React2.createElement(Text2, { color: "white" }, cmd.desc)
        )),
        scrollOffset < maxOffset && React2.createElement(
          Box2,
          {},
          React2.createElement(Text2, { color: "green", dim: true }, "  \u2193 " + (COMMANDS.length - scrollOffset - MAX_VISIBLE) + " more")
        ),
        React2.createElement(
          Box2,
          { marginTop: 0 },
          React2.createElement(Text2, { color: "green" }, "  \u2191\u2193 scroll  Esc=close  Ctrl+K=palette  up/down=history")
        )
      );
    }
    module2.exports.CommandHelp = CommandHelp2;
  }
});

// src/components/CommandPalette.jsx
var require_CommandPalette = __commonJS({
  "src/components/CommandPalette.jsx"(exports2, module2) {
    var React2 = require("react");
    var { Box: Box2, Text: Text2, useInput: useInput2 } = require("ink");
    var COMMANDS = [
      { cmd: "init", desc: "Index your codebase for analysis" },
      { cmd: "init --force", desc: "Force re-index" },
      { cmd: "review", desc: "Scan for OWASP Top 10 vulnerabilities" },
      { cmd: "review --ai", desc: "Review with AI-powered deep analysis" },
      { cmd: "review --verify", desc: "Review + AI-verify findings (filter false positives)" },
      { cmd: "review --max-findings 10", desc: "Review (limit to top 10 findings)" },
      { cmd: "review --min-severity high", desc: "Review (only high+ severity)" },
      { cmd: "review --min-confidence medium", desc: "Review (only medium+ confidence)" },
      { cmd: "review --format sarif", desc: "Review \u2192 SARIF JSON output" },
      { cmd: "review --format json", desc: "Review \u2192 machine-readable JSON" },
      { cmd: "review --output file.json", desc: "Write review output to file" },
      { cmd: "deps", desc: "Check dependency vulnerabilities" },
      { cmd: "deps --online", desc: "Check deps with OSV.dev API" },
      { cmd: "deps --fail-on high", desc: "Deps check, fail on high+" },
      { cmd: "secrets", desc: "Scan for leaked credentials" },
      { cmd: "secrets --fail-on high", desc: "Secrets scan, fail on high+" },
      { cmd: "ask", desc: "Ask a security question (uses AI)" },
      { cmd: "report", desc: "Generate security report" },
      { cmd: "report --format html", desc: "Report \u2192 exports cipher-ai-report.html dashboard" },
      { cmd: "report --type executive", desc: "Executive summary report" },
      { cmd: "fix --list", desc: "List fixable findings" },
      { cmd: "fix --dry-run", desc: "Preview fixes without applying" },
      { cmd: "fix --verify", desc: "Fix + compile-check each patch (revert broken fixes)" },
      { cmd: "fix --pr", desc: "Fix + open a GitHub PR with the fixes" },
      { cmd: "attack", desc: "Discover attack chains" },
      { cmd: "attack --flow", desc: "Attack chains + real data-flow evidence" },
      { cmd: "attack --chain privilege-escalation", desc: "Attack chains filtered by type" },
      { cmd: "attack --depth 5", desc: "Deeper attack chain analysis" },
      { cmd: 'trace "can users become admin?"', desc: "Trace untrusted data across files (taint flow)" },
      { cmd: 'trace --ai "is this SQL injectable?"', desc: "Trace + AI-enriched path analysis" },
      { cmd: 'trace --json "user input reaches exec"', desc: "Trace \u2192 JSON output" },
      { cmd: "pr --dry-run", desc: "Preview a PR security review comment" },
      { cmd: "pr --diff", desc: "Diff-aware PR review (changed lines only + inline comments)" },
      { cmd: "watch", desc: "Monitor for new findings (every 6h, saved state)" },
      { cmd: "watch --once", desc: "Watch: single scan, report what is new" },
      { cmd: "watch --pr", desc: "Watch + auto-fix new findings via GitHub PR" },
      { cmd: "watch --interval 60", desc: "Watch: scan every 60 minutes" },
      { cmd: "ci", desc: "Run all 5 scans (review+secrets+deps+zeroday+attack)" },
      { cmd: "ci --format json", desc: "CI \u2192 machine-readable JSON" },
      { cmd: "ci --format json --output ci.json", desc: "CI \u2192 JSON written to file" },
      { cmd: "ci --fail-on critical", desc: "CI: fail only on critical findings" },
      { cmd: "config", desc: "Show or set configuration" },
      { cmd: "config set provider groq", desc: "Switch AI provider \u2192 Groq" },
      { cmd: "config set provider openai", desc: "Switch AI provider \u2192 OpenAI" },
      { cmd: "config set provider anthropic", desc: "Switch AI provider \u2192 Anthropic" },
      { cmd: "pentest", desc: "Autonomous AI security engineer (agent hunts + reports)" },
      { cmd: 'pentest "hunt for exploitable vulnerabilities"', desc: "Pentest with a default objective" },
      { cmd: 'pentest "can users escalate privileges?"', desc: "Pentest with a specific objective" },
      { cmd: "pentest --json", desc: "Pentest \u2192 machine-readable JSON" },
      { cmd: "pentest --max-turns 60", desc: "Pentest with a larger agent budget" },
      { cmd: "pentest --url http://localhost:8080", desc: "Live mode: login, TOTP, exploit validators" },
      { cmd: 'pentest "hunt and exploit vulnerabilities" --url http://localhost:8080', desc: "Live pentest: prove exploits against a running target" },
      { cmd: 'pentest "hunt and exploit vulnerabilities" --url http://localhost:8080 --sub-agents 6', desc: "Live pentest: parallel specialist sub-agents" },
      { cmd: 'pentest "test the login" --url http://localhost:8080 --config app.yaml', desc: "Live pentest with YAML config: auth, ROE, scope rules" },
      { cmd: "zeroday", desc: "3-layer zero-day anomaly detection" },
      { cmd: "zeroday --ai", desc: "Zero-day + AI-powered analysis" },
      { cmd: "zeroday --anomaly-only", desc: "Zero-day: anomaly layer only" },
      { cmd: "zeroday --no-flow", desc: "Zero-day: skip taint flow analysis" },
      { cmd: "zeroday --format json", desc: "Zero-day \u2192 JSON output" },
      { cmd: "zeroday --format sarif", desc: "Zero-day \u2192 SARIF JSON output" },
      { cmd: "sbom", desc: "Generate CycloneDX SBOM" },
      { cmd: "sbom --format spdx", desc: "Generate SPDX SBOM" },
      { cmd: "sbom --output bom.json", desc: "Write SBOM to file" },
      { cmd: "---", desc: "---" },
      { cmd: "model", desc: "Show or switch AI model" },
      { cmd: "model llama-3.3-70b-versatile", desc: "Groq \u2014 default chat model" },
      { cmd: "model mixtral-8x7b-32768", desc: "Groq \u2014 32K context" },
      { cmd: "model gemma2-9b-it", desc: "Groq \u2014 fast & light" },
      { cmd: "model gpt-4o-mini", desc: "OpenAI \u2014 default" },
      { cmd: "model claude-3-7-sonnet-20250219", desc: "Anthropic \u2014 default" },
      { cmd: "status", desc: "Show index and API key status" },
      { cmd: "---", desc: "---" },
      { cmd: "clear", desc: "Clear messages" },
      { cmd: "exit", desc: "Exit the TUI" }
    ];
    var MAX_VISIBLE = 10;
    function CommandPalette2({ onSelect, onClose }) {
      const [selectedIdx, setSelectedIdx] = React2.useState(0);
      const [search, setSearch] = React2.useState("");
      const [scrollOffset, setScrollOffset] = React2.useState(0);
      const filtered = COMMANDS.filter((c) => c.cmd !== "---" && c.cmd.toLowerCase().includes(search.toLowerCase()));
      const maxOffset = Math.max(0, filtered.length - MAX_VISIBLE);
      useInput2((input, key) => {
        if (key.escape) {
          onClose();
          return;
        }
        if (key.return && filtered[selectedIdx]) {
          onSelect(filtered[selectedIdx].cmd);
          return;
        }
        if (key.upArrow) {
          const newIdx = Math.max(0, selectedIdx - 1);
          setSelectedIdx(newIdx);
          if (newIdx < scrollOffset) setScrollOffset(newIdx);
          return;
        }
        if (key.downArrow) {
          const newIdx = Math.min(filtered.length - 1, selectedIdx + 1);
          setSelectedIdx(newIdx);
          if (newIdx >= scrollOffset + MAX_VISIBLE) setScrollOffset(newIdx - MAX_VISIBLE + 1);
          return;
        }
        if (key.backspace || key.delete) {
          setSearch((p) => p.slice(0, -1));
          setSelectedIdx(0);
          setScrollOffset(0);
          return;
        }
        if (input.length >= 1) {
          setSearch((p) => p + input);
          setSelectedIdx(0);
          setScrollOffset(0);
        }
      });
      const visible = filtered.slice(scrollOffset, scrollOffset + MAX_VISIBLE);
      return React2.createElement(
        Box2,
        {
          flexDirection: "column",
          borderStyle: "round",
          borderColor: "yellow",
          padding: 1,
          marginLeft: 2,
          marginRight: 2,
          marginTop: 1,
          height: MAX_VISIBLE + 5
        },
        React2.createElement(
          Box2,
          { marginBottom: 1 },
          React2.createElement(Text2, { bold: true, color: "yellow" }, " Command Palette ")
        ),
        React2.createElement(
          Box2,
          { borderStyle: "single", borderColor: "green", paddingLeft: 1, marginBottom: 1 },
          React2.createElement(Text2, { color: "green" }, "> "),
          React2.createElement(Text2, { color: search ? "yellow" : "green" }, search || "Type to filter...")
        ),
        scrollOffset > 0 && React2.createElement(
          Box2,
          {},
          React2.createElement(Text2, { color: "green", dim: true }, "  \u2191 " + scrollOffset + " more")
        ),
        ...visible.map((cmd, i) => {
          const globalIdx = scrollOffset + i;
          return React2.createElement(
            Box2,
            {
              key: cmd.cmd,
              flexDirection: "row",
              backgroundColor: globalIdx === selectedIdx ? "green" : void 0
            },
            React2.createElement(
              Box2,
              { width: 24 },
              React2.createElement(Text2, { color: "yellow", bold: globalIdx === selectedIdx }, "  " + cmd.cmd)
            ),
            React2.createElement(Text2, { color: globalIdx === selectedIdx ? "yellow" : "white" }, cmd.desc)
          );
        }),
        scrollOffset < maxOffset && React2.createElement(
          Box2,
          {},
          React2.createElement(Text2, { color: "green", dim: true }, "  \u2193 " + (filtered.length - scrollOffset - MAX_VISIBLE) + " more")
        ),
        React2.createElement(
          Box2,
          { marginTop: 0 },
          React2.createElement(Text2, { color: "green" }, "\u2191\u2193 Navigate  Enter Select  Esc Close")
        )
      );
    }
    module2.exports.CommandPalette = CommandPalette2;
  }
});

// src/utils/binary.js
var require_binary = __commonJS({
  "src/utils/binary.js"(exports2, module2) {
    var fs = require("fs");
    var path = require("path");
    var os = require("os");
    var isWin = os.platform() === "win32";
    function toWslPath(winPath) {
      if (!isWin) return winPath;
      return winPath.replace(/^([A-Za-z]):\\/, (_, d) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/");
    }
    function findBinaryPath() {
      const binaryName = "cipher-ai";
      const winBinaryName = "cipher-ai.exe";
      const wslPaths = [
        // From dist/ (bundled)
        path.resolve(__dirname, "..", "..", "target", "x86_64-unknown-linux-gnu", "release", binaryName),
        // From src/utils/ (unbundled)
        path.resolve(__dirname, "..", "..", "..", "target", "x86_64-unknown-linux-gnu", "release", binaryName)
      ];
      for (const p of wslPaths) {
        if (fs.existsSync(p)) {
          return { path: toWslPath(path.resolve(p)), useWSL: true };
        }
      }
      const winPaths = [
        // From dist/ (bundled)
        path.resolve(__dirname, "..", "..", "target", "release", winBinaryName),
        path.resolve(__dirname, "..", "..", "target", "debug", winBinaryName),
        path.resolve(__dirname, "..", "..", "target", "x86_64-pc-windows-gnullvm", "release", winBinaryName),
        path.resolve(__dirname, "..", "..", "target", "x86_64-pc-windows-gnu", "release", winBinaryName),
        // From src/utils/ (unbundled)
        path.resolve(__dirname, "..", "..", "..", "target", "release", winBinaryName),
        path.resolve(__dirname, "..", "..", "..", "target", "debug", winBinaryName),
        path.resolve(__dirname, "..", "..", "..", "target", "x86_64-pc-windows-gnullvm", "release", winBinaryName),
        path.resolve(__dirname, "..", "..", "..", "target", "x86_64-pc-windows-gnu", "release", winBinaryName)
      ];
      for (const p of winPaths) {
        if (fs.existsSync(p)) return { path: path.resolve(p), useWSL: false };
      }
      const homeDir = os.homedir();
      const globalWsl = path.join(homeDir, ".cipher", "bin", binaryName);
      if (fs.existsSync(globalWsl)) {
        return { path: toWslPath(path.resolve(globalWsl)), useWSL: isWin };
      }
      const globalWin = path.join(homeDir, ".cipher", "bin", winBinaryName);
      if (fs.existsSync(globalWin)) {
        return { path: path.resolve(globalWin), useWSL: false };
      }
      try {
        const which = require("child_process").execFileSync(
          isWin ? "where" : "which",
          [winBinaryName],
          { encoding: "utf-8", stdio: "pipe", timeout: 5e3 }
        );
        const found = which.split("\n")[0].trim();
        if (found && fs.existsSync(found)) {
          return { path: path.resolve(found), useWSL: false };
        }
      } catch {
        try {
          const which = require("child_process").execFileSync(
            isWin ? "where" : "which",
            [binaryName],
            { encoding: "utf-8", stdio: "pipe", timeout: 5e3 }
          );
          const found = which.split("\n")[0].trim();
          if (found && fs.existsSync(found)) {
            return { path: toWslPath(path.resolve(found)), useWSL: isWin };
          }
        } catch {
        }
      }
      return null;
    }
    module2.exports.findBinaryPath = findBinaryPath;
  }
});

// src/commands/runner.js
var require_runner = __commonJS({
  "src/commands/runner.js"(exports2, module2) {
    var { spawn } = require("child_process");
    var { findBinaryPath } = require_binary();
    var BINARY_TIMEOUT_MS = 12e4;
    var PENTEST_TIMEOUT_MS = 6e5;
    var MAX_STDOUT_BYTES = 10 * 1024 * 1024;
    var MAX_STDERR_BYTES = 5 * 1024 * 1024;
    function commandTimeoutMs(args) {
      return args[0] === "pentest" ? PENTEST_TIMEOUT_MS : BINARY_TIMEOUT_MS;
    }
    var currentModel = null;
    function setModel2(model) {
      currentModel = model || null;
    }
    function runCommand2(args, signal) {
      return new Promise((resolve) => {
        const result = findBinaryPath();
        if (!result) {
          resolve({
            ok: false,
            stdout: "",
            stderr: "",
            error: "CipherAI Rust binary not found. Build it: cargo build --release"
          });
          return;
        }
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        let killed = false;
        const timers = [];
        const timeoutMs = commandTimeoutMs(args);
        const command = result.useWSL ? "wsl" : result.path;
        const cmdArgs = result.useWSL ? [result.path, ...args] : args;
        const env = { ...process.env };
        if (currentModel) env.CIPHER_AI_MODEL = currentModel;
        const child = spawn(command, cmdArgs, {
          cwd: process.cwd(),
          encoding: "utf-8",
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
          env
        });
        const timeoutTimer = setTimeout(() => {
          timedOut = true;
          child.killed || child.kill("SIGTERM");
          setTimeout(() => {
            child.killed || child.kill("SIGKILL");
          }, 5e3).unref();
        }, timeoutMs);
        timers.push(timeoutTimer);
        let abortHandler;
        if (signal) {
          abortHandler = () => {
            killed = true;
            clearTimeout(timeoutTimer);
            child.killed || child.kill("SIGTERM");
            setTimeout(() => {
              child.killed || child.kill("SIGKILL");
            }, 3e3).unref();
          };
          signal.addEventListener("abort", abortHandler, { once: true });
        }
        let outputLimitHit = false;
        child.stdout.on("data", (data) => {
          if (stdout.length < MAX_STDOUT_BYTES) {
            stdout += data;
          } else if (!killed) {
            killed = true;
            outputLimitHit = true;
            clearTimeout(timeoutTimer);
            child.kill("SIGTERM");
          }
        });
        child.stderr.on("data", (data) => {
          if (stderr.length < MAX_STDERR_BYTES) {
            stderr += data;
          }
        });
        child.on("error", (err) => {
          timers.forEach(clearTimeout);
          if (abortHandler && signal) {
            signal.removeEventListener("abort", abortHandler);
          }
          resolve({
            ok: false,
            stdout,
            stderr,
            error: err.message
          });
        });
        child.on("close", (code) => {
          timers.forEach(clearTimeout);
          if (abortHandler && signal) {
            signal.removeEventListener("abort", abortHandler);
          }
          if (killed) {
            const msg = outputLimitHit ? "Command output exceeded 10MB limit. Try running on a more specific directory." : "Command was cancelled";
            resolve({
              ok: false,
              stdout,
              stderr,
              error: msg
            });
            return;
          }
          if (timedOut) {
            resolve({
              ok: false,
              stdout,
              stderr,
              error: "Command timed out after " + timeoutMs / 1e3 + "s. Try on a smaller directory or use --filter flags."
            });
            return;
          }
          if (code !== 0) {
            const stderrMsg = stderr.trim();
            const stdoutLines = stdout.trim().split("\n").filter((l) => l.trim());
            const errorLine = stdoutLines.reverse().find(
              (l) => /[✗×✕✖]\s/.test(l) || /^\s*error:/i.test(l) || /check failed/i.test(l) || /FAILED/i.test(l)
            );
            const errorMsg = stderrMsg || (errorLine ? errorLine.trim() : "") || "Command failed with exit code " + code;
            resolve({
              ok: false,
              stdout,
              stderr,
              error: errorMsg
            });
            return;
          }
          resolve({
            ok: true,
            stdout,
            stderr
          });
        });
        timeoutTimer.unref();
      });
    }
    module2.exports.runCommand = runCommand2;
    module2.exports.setModel = setModel2;
  }
});

// src/index.jsx
var React = require("react");
var { render, Box, Text, useApp, useInput } = require("ink");
var { ChatArea } = require_ChatArea();
var { InputBox } = require_InputBox();
var { StatusBar } = require_StatusBar();
var { CommandHelp } = require_CommandHelp();
var { CommandPalette } = require_CommandPalette();
var { runCommand, setModel } = require_runner();
var MODELS = [
  "llama-3.3-70b-versatile",
  // Groq
  "mixtral-8x7b-32768",
  // Groq
  "gemma2-9b-it",
  // Groq
  "gpt-4o-mini",
  // OpenAI
  "claude-3-7-sonnet-20250219"
  // Anthropic
];
var COMMAND_LIST = ["init", "review", "deps", "secrets", "ask", "report", "fix", "attack", "trace", "pr", "watch", "status", "ci", "config", "pentest", "zeroday", "sbom"];
function isQuestion(text) {
  const qWords = [
    "what",
    "how",
    "why",
    "is",
    "can",
    "does",
    "are",
    "do",
    "will",
    "would",
    "could",
    "should",
    "has",
    "have",
    "did",
    "was",
    "were",
    "find",
    "show",
    "list",
    "tell",
    "explain",
    "describe",
    "review"
  ];
  const lower = text.toLowerCase().trim();
  if (lower.endsWith("?")) return true;
  return qWords.some((w) => lower.startsWith(w));
}
function App() {
  const { exit } = useApp();
  const [messages, setMessages] = React.useState([{
    id: "welcome",
    type: "system",
    text: ""
  }]);
  const [input, setInput] = React.useState("");
  const [isRunning, setIsRunning] = React.useState(false);
  const [showHelp, setShowHelp] = React.useState(false);
  const [showPalette, setShowPalette] = React.useState(false);
  const [showAskPrompt, setShowAskPrompt] = React.useState(false);
  const [status, setStatus] = React.useState({ index: "unknown", apiKey: "unknown", provider: "groq" });
  const [modelIdx, setModelIdx] = React.useState(0);
  const [history, setHistory] = React.useState([]);
  const [historyIdx, setHistoryIdx] = React.useState(-1);
  const abortRef = React.useRef(null);
  useInput((_input, key) => {
    if (key.ctrl && _input === "k") {
      setShowHelp(false);
      setShowPalette((p) => !p);
      return;
    }
    if (key.ctrl && _input === "l") {
      setMessages([{ id: "welcome", type: "system", text: "" }]);
      return;
    }
    if (key.ctrl && _input === "m") {
      const n = (modelIdx + 1) % MODELS.length;
      setModelIdx(n);
      setModel(MODELS[n]);
      return;
    }
    if (key.escape) {
      if (showHelp) {
        setShowHelp(false);
        return;
      }
      if (showPalette) {
        setShowPalette(false);
        return;
      }
      if (showAskPrompt) {
        setShowAskPrompt(false);
        return;
      }
      if (isRunning && abortRef.current) {
        abortRef.current.abort();
        addMessage("system", "Command cancelled.");
        setIsRunning(false);
        return;
      }
    }
  });
  function navigateHistory(direction) {
    if (history.length === 0) return;
    if (direction === "up") {
      const newIdx = historyIdx < history.length - 1 ? historyIdx + 1 : history.length - 1;
      setHistoryIdx(newIdx);
      setInput(history[history.length - 1 - newIdx]);
    } else if (direction === "down") {
      const newIdx = historyIdx - 1;
      if (newIdx < 0) {
        setHistoryIdx(-1);
        setInput("");
      } else {
        setHistoryIdx(newIdx);
        setInput(history[history.length - 1 - newIdx]);
      }
    }
  }
  React.useEffect(() => {
    runCommand(["status"]).then((r) => {
      if (r.ok) {
        const out = r.stdout.toLowerCase();
        setStatus((prev) => ({
          ...prev,
          index: out.includes("not indexed") ? "not indexed" : out.includes("index:") ? "indexed" : "unknown"
        }));
      }
    }).catch(() => {
    });
    runCommand(["config", "get", "provider"]).then((r) => {
      const provider = r.ok && r.stdout.trim() ? r.stdout.trim() : "groq";
      setStatus((prev) => ({ ...prev, provider }));
      return runCommand(["config", "get", provider + "-api-key"]);
    }).then((r2) => {
      if (r2 && r2.ok) {
        setStatus((prev) => ({
          ...prev,
          apiKey: r2.stdout.includes("not set") ? "missing" : "set"
        }));
      }
    }).catch(() => {
    });
  }, []);
  function addMessage(type, text) {
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    setMessages((prev) => [...prev, { id, type, text }]);
  }
  async function handleSubmit(value) {
    const trimmed = value.trim();
    if (!trimmed || isRunning) return;
    setHistory((prev) => [...prev, trimmed]);
    if (showAskPrompt) {
      setShowAskPrompt(false);
      setInput("");
      await handleCommand("/ask " + trimmed);
      return;
    }
    setInput("");
    if (trimmed.startsWith("/")) {
      await handleCommand(trimmed);
    } else if (isQuestion(trimmed)) {
      addMessage("user", trimmed);
      await handleCommand("/ask " + trimmed);
    } else {
      addMessage("error", "Unknown input. Use / for commands or ask a question. Run /help.");
    }
  }
  function handleInputChange(val) {
    setInput(val);
  }
  async function handleCommand(input2) {
    const parts = input2.slice(1).trim().split(/\s+/);
    const command = parts[0]?.toLowerCase();
    const cmdArgs = parts.slice(1).map((a) => a.replace(/^["']|["']$/g, ""));
    switch (command) {
      case "help":
      case "h":
        setShowHelp(true);
        return;
      case "exit":
      case "quit":
      case "q":
        exit();
        return;
      case "clear":
      case "cls":
        setMessages([{ id: "welcome", type: "system", text: "" }]);
        return;
      case "model":
        if (cmdArgs.length > 0) {
          const idx = MODELS.indexOf(cmdArgs[0]);
          if (idx >= 0) {
            setModelIdx(idx);
            setModel(MODELS[idx]);
            addMessage("result", "Model switched to: " + MODELS[idx]);
          } else {
            addMessage("error", "Unknown model. Available: " + MODELS.join(", "));
          }
        } else {
          addMessage("result", "Current model: " + MODELS[modelIdx] + "\nSwitch: /model <name>\nAvailable: " + MODELS.join(", "));
        }
        return;
      case "ask":
        if (cmdArgs.length === 0) {
          setShowAskPrompt(true);
          addMessage("system", "Type your question and press Enter, or press Esc to cancel.");
          return;
        }
        break;
    }
    addMessage("user", input2);
    const isKnown = COMMAND_LIST.includes(command);
    if (!isKnown) {
      addMessage("error", "Unknown command: /" + command + "\nRun /help for available commands.");
      return;
    }
    const labels = {
      init: "Indexing project...",
      review: "Running security review...",
      deps: "Checking dependencies...",
      secrets: "Scanning for secrets...",
      ask: "Asking AI...",
      report: "Generating report...",
      fix: "Generating fix...",
      attack: "Analyzing attack paths...",
      trace: "Tracing data flow...",
      pr: "Reviewing pull request...",
      watch: "Monitoring for new findings...",
      status: "Checking status...",
      ci: "Running all scans...",
      config: "Configuring...",
      pentest: "Running autonomous pentest...",
      zeroday: "Running zero-day analysis...",
      sbom: "Generating SBOM..."
    };
    addMessage("command", labels[command] || "Running " + command + "...");
    setIsRunning(true);
    setHistoryIdx(-1);
    const abortController = new AbortController();
    abortRef.current = abortController;
    const result = await runCommand([command, ...cmdArgs], abortController.signal);
    setIsRunning(false);
    abortRef.current = null;
    if (result.ok) {
      addMessage("result", result.stdout.trim() || result.stderr.trim() || "(no output)");
    } else {
      const outMsg = result.stdout.trim();
      const errMsg = result.stderr.trim() || result.error || "Command failed";
      if (outMsg) {
        addMessage("result", outMsg);
        if (!outMsg.includes(errMsg.replace(/[✗×✕✖]\s*/g, "").trim())) {
          addMessage("error", errMsg);
        }
      } else {
        addMessage("error", errMsg);
      }
    }
  }
  return React.createElement(
    Box,
    { flexDirection: "column", height: "100%", width: "100%" },
    React.createElement(ChatArea, { messages, isRunning, model: MODELS[modelIdx], showAskPrompt }),
    showHelp && React.createElement(CommandHelp, { onClose: () => setShowHelp(false) }),
    showPalette && React.createElement(CommandPalette, {
      onSelect: (cmd) => {
        setShowPalette(false);
        if (cmd === "exit") {
          exit();
          return;
        }
        if (cmd === "clear") {
          setMessages([{ id: "welcome", type: "system", text: "" }]);
          return;
        }
        if (cmd.startsWith("model ")) {
          const m = cmd.slice(6);
          const idx = MODELS.indexOf(m);
          if (idx >= 0) {
            setModelIdx(idx);
            setModel(MODELS[idx]);
          }
          return;
        }
        handleSubmit("/" + cmd);
      },
      onClose: () => setShowPalette(false)
    }),
    React.createElement(InputBox, {
      value: input,
      onChange: handleInputChange,
      onSubmit: handleSubmit,
      isRunning,
      showAskPrompt,
      onNavigateHistory: navigateHistory
    }),
    React.createElement(StatusBar, { status, model: MODELS[modelIdx], isRunning, messageCount: messages.length })
  );
}
var { waitUntilExit } = render(React.createElement(App));
process.on("SIGINT", () => process.exit(0));
waitUntilExit().catch(() => {
});
